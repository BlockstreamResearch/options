//! Covenant Miniscripts for Options on elements
//! The variable names are same as of the document for ease of review
use std::sync::Arc;

/// (Mini)Scripts related to covenants
use miniscript::{
    self,
    bitcoin::XOnlyPublicKey,
    descriptor::{SinglePub, SinglePubKey, TapTree, Tr},
    elements::{
        confidential::Asset,
        encode::serialize,
        hashes::hex::ToHex,
        opcodes, script,
        secp256k1_zkp::{Secp256k1, Signing},
        AssetId, Script,
    },
    extensions::CovExtArgs,
    translate_hash_clone, CovenantExt, DefiniteDescriptorKey, Descriptor, DescriptorPublicKey, Tap,
    TranslatePk, Translator,
};

use crate::contract::OptionsContract;
use crate::UserCovType;

/// type alias for miniscript with Tap script Ms with extensions
type MsTap = miniscript::Miniscript<XOnlyPublicKey, Tap, CovenantExt<CovExtArgs>>;
/// type alias for taproot descriptor for extensions
pub type TrDesc = Tr<XOnlyPublicKey, CovenantExt<CovExtArgs>>;

impl OptionsContract {
    /// Creates a funding descriptor from this options contract.
    /// Creates Re-issuance covenant Descriptor. Used for funding/creating new contracts.
    /// Returns:
    ///     - The descriptor corresponding to CRT RT.
    pub fn funding_desc<C: Signing>(&self, secp: &Secp256k1<C>) -> TrDesc {
        // Same variables from the scratchpad doc
        let a1 = "num64_eq(inp_v(0),out_v(0))";
        let a2 = "num64_eq(inp_v(1),out_v(1))";
        let a3 = format!("and_v(v:{},{})", a1, a2);

        let crt_rt_blinded_a = self.crt_rt_blinds(secp)[0].0;
        let crt_rt_blinded_b = self.crt_rt_blinds(secp)[1].0;
        let ort_rt_blinded_a = self.ort_rt_blinds(secp)[0].0;
        let ort_rt_blinded_b = self.ort_rt_blinds(secp)[1].0;
        let a4 = format!("asset_eq(out_asset(0),{})", crt_rt_blinded_a);
        let a5 = format!("asset_eq(out_asset(0),{})", crt_rt_blinded_b);

        let a6 = format!("or_b({},a:{})", a4, a5);

        let a7 = format!("asset_eq(out_asset(1),{})", ort_rt_blinded_a);
        let a8 = format!("asset_eq(out_asset(1),{})", ort_rt_blinded_b);

        let a9 = format!("or_b({},a:{})", a7, a8);
        let a10 = format!("and_v(v:{},{})", a6, a9);

        let a11 = "spk_eq(inp_spk(0),out_spk(0))";
        let a12 = "spk_eq(inp_spk(1),out_spk(1))";
        let a13 = format!("and_v(v:{},{})", a11, a12);

        let a14 = format!("and_v(v:and_v(v:{},{}),{})", a3, a10, a13);

        let b1 = "num64_eq(inp_issue_v(0),inp_issue_v(1))";
        let b2 = format!(
            "num64_eq(mul(inp_issue_v(0),{}),out_v(2))",
            self.params().contract_size
        );

        let coll_asset = serialize(&Asset::Explicit(self.params().coll_asset)).to_hex();
        let b3 = format!("asset_eq(out_asset(2),{})", coll_asset);

        let coll_desc = self.coll_desc();
        let coll_spk = coll_desc.script_pubkey();
        let b4 = format!("spk_eq(out_spk(2),{})", coll_spk.to_hex());

        let b5 = format!("and_v(v:{},{})", b1, b2);
        let b6 = format!("and_v(v:{},{})", b3, b4);
        let b7 = format!("and_v(v:{},{})", b5, b6);

        let c1 = "curr_idx_eq(0)";
        let c2 = "curr_idx_eq(1)";

        let c3 = format!("or_b({},a:{})", c1, c2);

        let rt_cov = format!("and_v(v:{},and_v(v:{},{}))", a14, b7, c3);

        let rt_ms = MsTap::from_str_insane(&rt_cov).expect("Valid RT issuance Miniscript");
        let desc = TrDesc::new(self.unspend_key(), Some(TapTree::Leaf(Arc::new(rt_ms))))
            .expect("Parsing a valid manually constructed descriptor");
        desc
    }

    /// Private helper function to check whether we need a change output
    /// If there is a change output, check that change amount/amount/spk
    /// correctly enforced in the covenant
    fn coll_change_e7(&self, cov_ty: UserCovType) -> String {
        let sz = match cov_ty {
            UserCovType::Collateral => self.params().contract_size,
            UserCovType::Settlement => self.params().strike_price,
        };
        let e1 = format!("num64_gt(curr_inp_v,mul({},out_v(0)))", sz);
        let e2 = format!("num64_eq(out_v(2),sub(curr_inp_v,mul({},out_v(0))))", sz);

        let e3 = "asset_eq(curr_inp_asset,out_asset(2))";
        let e4 = "spk_eq(curr_inp_spk,out_spk(2))";

        let e5 = format!("and_v(v:{},and_v(v:{},and_v(v:{},{})))", e1, e2, e3, e4);
        let e6 = format!("num64_eq(curr_inp_v,mul({},out_v(0)))", sz);

        let e7 = format!("or_d({},{})", e6, e5);
        e7
    }

    /// Creates the Collateral Miniscript Descriptor
    pub fn coll_desc(&self) -> TrDesc {
        // Create some tree using these three spend conditions.
        // We cannot use the string APIs to construct these because the
        // descriptor FromStr does not have a corresponding insane version
        // Using normal APIs, this would give a SigLessBranch which is true, but
        // at the same time the security of this covenant does not rely on signatures
        // in the spending utxo.
        // Roundabout HACK: Directly construct the tree
        use TapTree::{Leaf, Tree};
        let tree = Tree(
            Arc::new(Tree(
                Arc::new(Leaf(Arc::new(self.cancel_ms()))),
                Arc::new(Leaf(Arc::new(self.exec_ms()))),
            )),
            Arc::new(Leaf(Arc::new(self.expiry_ms()))),
        );
        TrDesc::new(self.unspend_key(), Some(tree)).expect("Tree depth < 128")
    }

    /// Miniscript corresponding to cancellation of an option.
    pub fn cancel_ms(&self) -> MsTap {
        let d1 = format!("asset_eq(out_asset(0),{})", asset_hex(self.crt()));
        let d2 = format!("asset_eq(out_asset(1),{})", asset_hex(self.ort()));
        let d3 = format!("and_v(v:{},{})", d1, d2);

        let d4 = "spk_eq(out_spk(0),out_spk(1))";
        let d5 = format!("spk_eq(out_spk(1),{})", op_return().to_hex());
        let d6 = format!("and_v(v:{},{})", d4, d5);

        let d7 = "num64_eq(out_v(0),out_v(1))";
        let d8 = format!("and_v(v:{},and_v(v:{},{}))", d3, d6, d7);

        let e7 = self.coll_change_e7(UserCovType::Collateral);

        let f1 = "curr_idx_eq(0)";
        let cancel = format!("and_v(v:{},and_v(v:{},{}))", d8, e7, f1);
        MsTap::from_str_insane(&cancel).expect("Valid tapscript miniscript construction")
    }

    /// Miniscript corresponding to execution of an option.
    pub fn exec_ms(&self) -> MsTap {
        let g1 = format!("after({})", self.params().start);

        let h1 = format!("asset_eq(out_asset(0),{})", asset_hex(self.ort()));
        let h2 = format!("spk_eq(out_spk(0),{})", op_return().to_hex());
        let h3 = format!("and_v(v:{},{})", h1, h2);

        let settle_spk = self.settle_desc().script_pubkey();
        let h4 = format!("spk_eq(out_spk(1),{})", settle_spk.to_hex());

        let settle_asset = serialize(&Asset::Explicit(self.params().settle_asset)).to_hex();
        let h5 = format!("asset_eq(out_asset(1),{})", settle_asset);
        let h6 = format!("and_v(v:{},{})", h4, h5);
        let h7 = format!(
            "num64_eq(mul({},out_v(0)),out_v(1))",
            self.params().strike_price
        );

        let h8 = format!("and_v(v:{},and_v(v:{},{}))", h3, h6, h7);
        let e7 = self.coll_change_e7(UserCovType::Collateral);
        let j1 = "curr_idx_eq(0)";

        let exec = format!("and_v(v:and_v(v:{},{}),and_v(v:{},{}))", h8, g1, e7, j1);
        MsTap::from_str_insane(&exec).expect("Valid miniscript contruction")
    }

    fn crt_asset_burn_l3(&self) -> String {
        let l1 = format!("asset_eq(out_asset(0),{})", asset_hex(self.crt()));
        let l2 = format!("spk_eq(out_spk(0),{})", op_return().to_hex());

        let l3 = format!("and_v(v:{},{})", l1, l2);
        l3
    }

    /// Miniscript corresponding to expiry of the contract
    pub fn expiry_ms(&self) -> MsTap {
        let k1 = format!("after({})", self.params().expiry);
        let l3 = self.crt_asset_burn_l3();
        let e7 = self.coll_change_e7(UserCovType::Collateral);
        let m1 = "curr_idx_eq(0)";

        let expiry = format!("and_v(v:and_v(v:{},{}),and_v(v:{},{}))", l3, k1, e7, m1);
        MsTap::from_str_insane(&expiry).expect("Valid miniscript contruction")
    }

    /// Descriptor corresponding to settlement contract
    pub fn settle_desc(&self) -> TrDesc {
        let l3 = self.crt_asset_burn_l3();
        let e7 = self.coll_change_e7(UserCovType::Settlement);
        let n1 = "curr_idx_eq(0)";
        let claim = format!("and_v(v:and_v(v:{},{}),{})", l3, e7, n1);

        // Need to use insane APIs because miniscript cannot analyze these as safe
        let claim_ms = MsTap::from_str_insane(&claim).expect("Valid miniscript");
        // The descriptor APIs don't have an insane version :(. So, we must construct these manually
        TrDesc::new(self.unspend_key(), Some(TapTree::Leaf(Arc::new(claim_ms))))
            .expect("Valid depth tree")
    }
}

// New op_return script with no data
pub(crate) fn op_return() -> Script {
    script::Builder::new()
        .push_opcode(opcodes::all::OP_RETURN)
        .into_script()
}

// Helper method: This should really be upstream
fn asset_hex(assetid: AssetId) -> String {
    let bytes = serialize(&Asset::Explicit(assetid));
    bytes.to_hex()
}

/// Translate the given Tr descriptor to Descriptor<DefiniteDescriptorKey>
pub(crate) fn translate_xpk_desc_pubkey(
    desc: TrDesc,
) -> Descriptor<DefiniteDescriptorKey, CovenantExt<CovExtArgs>> {
    pub struct DummyTranslator;

    impl Translator<XOnlyPublicKey, DefiniteDescriptorKey, ()> for DummyTranslator {
        fn pk(&mut self, pk: &XOnlyPublicKey) -> Result<DefiniteDescriptorKey, ()> {
            let key = DescriptorPublicKey::Single(SinglePub {
                origin: None,
                key: SinglePubKey::XOnly(*pk),
            });
            Ok(key.at_derivation_index(0))
        }

        translate_hash_clone!(XOnlyPublicKey, DefiniteDescriptorKey, ());
    }
    let desc = Descriptor::TrExt(desc);
    desc.translate_pk(&mut DummyTranslator).unwrap()
}

#[cfg(test)]
mod tests {

    use std::str::FromStr;

    use miniscript::elements::confidential::{AssetBlindingFactor, Value, ValueBlindingFactor};
    use miniscript::elements::encode::deserialize;
    use miniscript::elements::hashes::hex::FromHex;
    use miniscript::elements::taproot::LeafVersion;
    use miniscript::elements::{AddressParams, OutPoint, Transaction, TxOut, Txid};

    use super::*;
    use crate::contract::Consts;
    use crate::BaseParams;

    #[test]
    fn test_cov_desc() {
        const PARAMS: &'static AddressParams = &AddressParams::ELEMENTS; // edit this to liquid if needed
                                                                         // edit these as you need them
        let params = BaseParams {
            contract_size: 100_000,
            expiry: 1659640176, // UNIX timestamp
            start: 1659640076,
            strike_price: 20_000,
            coll_asset: AssetId::from_str(
                "3d8f49e01b8b2eab8bae136c9c0db8f0c6dce48cdeac3f3784b7af2844d523c8",
            )
            .unwrap(), // Note that asset id is parsed reverse as per elements convention
            settle_asset: AssetId::from_str(
                "cc4b500625764881971716718c9305da17363e4e97b6bcd26b30c9627dbe3868",
            )
            .unwrap(), //
        };
        let crt_rt_issue_prevout = OutPoint {
            txid: Txid::from_str(
                "5efe259e7b13724eb89ab0ee71739cdeeb04c6fb18d2851385c621902ee9cb94",
            )
            .unwrap(), // parsed reverse as per convention
            vout: 0,
        };
        let ort_rt_issue_prevout = OutPoint {
            txid: Txid::from_str(
                "5efe259e7b13724eb89ab0ee71739cdeeb04c6fb18d2851385c621902ee9cb94",
            )
            .unwrap(), // parsed reverse as per convention
            vout: 1,
        };

        let secp = Secp256k1::new();
        let contract = OptionsContract::new(params, crt_rt_issue_prevout, ort_rt_issue_prevout);
        let rt_desc = contract.funding_desc(&secp);

        let coll_desc = contract.coll_desc();
        let settle_desc = contract.settle_desc();

        let arr = [
            ("ORT/CRT RT Descriptor", rt_desc),
            ("Settlement Descriptor", settle_desc),
        ];

        fn print_control_blk(desc: &TrDesc, ms: &MsTap, name: &str) {
            let blk = desc
                .spend_info()
                .control_block(&(ms.encode(), LeafVersion::default()))
                .unwrap();
            println!(
                "Control block for {} script : {} ",
                name,
                blk.serialize().to_hex()
            );
        }

        for (name, desc) in arr {
            println!("Address for {} : {}", name, desc.address(None, &PARAMS));
            println!("Scriptpubkey for {} : {:x}", name, desc.script_pubkey());
            for (_, script) in desc.iter_scripts() {
                print_control_blk(&desc, script, name)
            }
            println!("\n"); // skip couple of lines
        }
        let coll_addr = coll_desc.address(None, &PARAMS);
        println!("Addr for Collateral desc : {}", coll_addr);
        println!("Spk for Collateral desc : {:x}", coll_desc.script_pubkey());

        print_control_blk(&coll_desc, &contract.cancel_ms(), "cancel");
        print_control_blk(&coll_desc, &contract.exec_ms(), "exec");
        print_control_blk(&coll_desc, &contract.expiry_ms(), "expiry");
    }

    #[test]
    fn test_asset_blinders() {
        let assetid =
            AssetId::from_str("0d427836e46e919653de03f0820e41b223af045a560f677f9f7b0a4b49181688")
                .unwrap();
        let abf = AssetBlindingFactor::one(); // can also be AssetBlindingFactor::two()

        let secp = Secp256k1::new();
        let conf_asset = Asset::new_confidential(&secp, assetid, abf);
        println!("{}", conf_asset.to_string());
    }

    #[test]
    fn compute_last_factor() {
        let secp = Secp256k1::new();
        let abfs_in = [
            "8987fdb72abbb9e267be82199a48ef532fb611399a459f5fae09894f2dc0af38",
            "110ac9e9b32a4c0bb7adfb4b1ddf6109265884c228e0d145ef22b9e9be679b52",
            "475523cfb711a46402da784a295fab089bcfa3e6bec7a5c9314c6f85ea867c5f",
        ];
        let abfs_in = abfs_in
            .iter()
            .map(|x| AssetBlindingFactor::from_str(x).unwrap())
            .collect::<Vec<_>>();
        let vbfs_in = [
            "3f8dc7822008d6a6a68e02427467a6491456fde62e0c7ce9644f334c6a73dfea",
            "3cb0b8d900c6594c6c070c487fd881b7d89700395766f48a8b663543c67c0388",
            "ea553ebf571bbd6dde5eb7d0820569aa1f105741057b03ae426f45ac7ff7da13",
        ];
        let vbfs_in = vbfs_in
            .iter()
            .map(|x| ValueBlindingFactor::from_str(x).unwrap())
            .collect::<Vec<_>>();
        let values_in = [1u64, 1, 98567];

        let last_value = 97567;
        let last_abf = AssetBlindingFactor::from_str(
            "15bf7e9786a7154e611ca5f82ede4bdc09eb24a56d10961bf28d7711d2bb67ae",
        )
        .unwrap();
        // AssetBlindingFactor::from_str(
        //     "32f0f4d5b4c7f68a5408e64e6f773154e9b1968e6ef0ec2e4e49c0a7d0d51e2b",
        // )
        // .unwrap();

        let abfs_out = [AssetBlindingFactor::one(), AssetBlindingFactor::one()];
        let vbfs_out = [ValueBlindingFactor::zero(), ValueBlindingFactor::zero()];
        let values_out = [1u64, 1];

        let mut inputs = vec![];
        for i in 0..values_in.len() {
            inputs.push((values_in[i], abfs_in[i], vbfs_in[i]));
        }

        let mut outputs = vec![];
        for i in 0..values_out.len() {
            outputs.push((values_out[i], abfs_out[i], vbfs_out[i]));
        }

        let last_vbf = ValueBlindingFactor::last(&secp, last_value, last_abf, &inputs, &outputs);
        println!("{}", last_vbf);

        // Dummy test with values all inputs abfs/vbfs/values as 1, output abfs as one, vbfs zero.
        let one_abf = AssetBlindingFactor::one();
        let one_vbf = ValueBlindingFactor::one();
        let zero_vbf = ValueBlindingFactor::zero();
        dbg!(ValueBlindingFactor::last(
            &secp,
            1,
            one_abf,
            &[(1, one_abf, one_vbf); 3],
            &[(1, one_abf, zero_vbf); 2]
        ));
    }

    #[test]
    #[rustfmt::skip]
    #[ignore]
    #[allow(unused_variables)]
    fn test_tx() {
        let tx_hex = "02000000010255c70467ef39a88539cf85098710dd0ffee46837f0fa5e917b14000fa5d84c0a000000800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000155c70467ef39a88539cf85098710dd0ffee46837f0fa5e917b14000fa5d84c0a0200008000fdffffff0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000001050bfa1f8f02b745b8f68d1f5b213ddde7c0ff02ba4679f1fea96a02cc1be18f932d0100000000000000010022512019cce487035bf5c77e533f701af8f2cf561990f042639ebff9149c76b7c469470ac7578838b1e1f73ee0f69f280780cd260749031bec3a8673b037c44ef67ce7590100000000000000010022512019cce487035bf5c77e533f701af8f2cf561990f042639ebff9149c76b7c469470af3d1a26bedbb1234b20831b7fdb6c7f0f81adb9dd2535adede6be08962189e70095042e8ff336b550fda433adda0fc8408834dd792317885c7b0efd3d70fc9a94502422608046cc52f03c98584ad83c05f7c5c9c9c3f92294edae9af0984cd0c5ebb160014bfe57b8d9a7746fdb48f5c0b09dc2f66017999ee0a27235eac352d68f0bce4af3e440d66cedfcf493aa048821cffa518278442205a0928b6f839fb25661925f3231f12ef829adab6afabe1412b93dfc1ea9f53d2c0bc02baad4fe5f7bc7096a18fa8f55c14cc384fc6d574b5b4c8500cd4e123c2419c2816001434fb4a09ce4ee7efcc4ba259b211f5cdd86cf0cf01499a818545f6bae39fc03b637f2a4e1e64e590cac1bc3a6f6d71aa4443654c1401000000000000175e00000000000000000000000000008304000bda1773e8488323845168858d2e7d275d9a13816e1d0e1aca180e8a57eb6a471d2158a8906d5e2c2be001bac943ab9cab4063536e1c546b40221fdf8db031a4bbaefb37bddf3379be78593f7b3e5ba705e705110ee4164e329b2d96ddcf888d0b8ad3d5b3d98e0313f6de2cc702fe422ac424489e06fb6805e68f17df6a02558d008304000daf868ebd60e300ad36c3d6bcdb967866dd577692691911a4e73fdb1c82b6916d2158a8906d5e2c2be001bac943ab9cab4063536e1c546b40221fdf8db031a4bbb11a112babcb67f270d5019bf98f9bafc8eff73534ae5834c2033505438d34a7ccf27d5f73e71e925b5262eb2b58eb3aab6fafadf7ef8c7713f55e5d4a1a36cf00630200030a0e355332aca665e3e988cb564f1c948f8869506bde3e66f34cddeda920948e5e36604ea9d19d4c40d1973cc291b81bca0d6ebb718bcfd59888370f672c1ec326cce30dcea8ba0c762e40680400e9070a0d6b8793c0557fc35bf15e88072ebcfd4e1060330000000000000001d9c7ab000e438b9158c50d0e5476517847791ea8463ff7755c62c6d6ef46e44b2397fb04dc80adfc0ff7e7c4571d86bb11123679503e40040b2752e454b7301a1b4ae6b08a15aaded52d810efe1fa540696fb74db52a0e820ee57080e3eeaf75b0e180dcfec9566d86f614378ed879229d31f4d3bf830c889538dd24463d5547202e667895223c16138d74d5197588f7e3b8e346e53f4a961df89391c34f9acf17c0124e1d42fdee1fdf1757db7bec772f0105a349b2f73170f535e8c52da40fd8eaed2ac75dcff0d19674a33f97e57fad0a17989e0ee85cbd2a7876ad42f8853e8b2b08a424254b3f2557ac7a7805cb6e9626836ec3d2c6908be98e6acf86a5b370a7af51b19d82279bd725b3dce3d7e209ade42920e3a2585db92e2d00b412274fc5989b227006c74b9d198964e5566eeb9adfd8ee5368fd7e2c28c5e68017451326ad27eefb242c5ca81c4ddcf9ad3476bdf7953434f442e5ab33557eefd7436b08424dbc599121a78cccf51bf98a401d019902cca37fb412cff0a443c50092332c8613cb1cd3b6951dd525d656fb6823c4ce7b7565c24e0c37fcdc2a10340af077b6bab4e0dce3c1b406e409e248d789d4607a2eb4a9d012a729104c1441cf6f0a3d261600acedcc0f8211a968381936938146abc66b10ae7541b78bb83b79d27e565f58a83e7f6063409bd7aa6736f85562b7058e2b8374b386e35fd132e30ed71be35fe3bb9e21638a32486bd05a858d0c4836485a8e2fa3c0ddb31f45e7fea4501faf33b6eb5050e7f873347a31436ef7d4d31ba5d56efb0dca19e3e6187a82be9330e4c1c56e0e7845b1a1ebb197bd1c18c781ec3ca14e217bf62596e23257cad26ee3b79277c95bef7a17afe2881795f8014fb2a318a117bfdc53f331477afee41b201d1a33e5bd7a7f0ffada5df2fbaeccc32071b3bac554eedd1771ec1c5cfd97a4d4c07d0169928f68b94a4fef404c093cc9378923defb70f5a10570805ff2f1e3d91cfe289e5c93a9c0b7df79d5dfa2ef19ca35f4e0f985bc311c06edf92763aa6ece97d8fab1dbdbef178f5d3b0a042eae4a6c78d4fd05da46257299b7e3878fdd19adbadc9565f215f79e685b4e4dcf80e8a0ad5706e510f504ab3c23b0d69d62621090ba852dc642a7d9a114860429a40e7c6e71660d65958346477a31441b1c9a3ca7d4c91099d0e7d9ce6bb61332bdef76e44dfa02c15cb52e817e08b0e6a075892a504f47c81521c434e917d78f445f54daa65c00a8d48677ec91aaf19b028ae95a8688e8b2cf8d0252a57d964fe75fad3bf7e47bc4ab769381a4ee0bba1f780ec99445397412043945857473e61eba3583e2a22bf721e57dd6f5aa4f00b75d9896a2a04ee99069c019339786cd98f9f1ca2bcb7c349c88aae4e349d13a9ddba991885f9213c3bd720d3af865ce3a27b6c486c5a958486bf813a32b36d5e47e887e3d32f46d38ffcce9099c154936a3f2debbe66f7e5718aadfae7709c9bb1e2f2c191ac8f437be04d1514f680406666ece9995eb433e4fc5c516f5a50633bec833cf5227fcb3751315ccd8a90ab202918189fe56b812b723defa66593ea8f96b2669ff9dddf48707faab894c36fe19d0daefd78c98b36a1110b0edf59ce116068e18e90e58f481fb0be3aef934b7f128c297ebc16aa5834f327103b183792a7b29284a86e5b11c1e0264e1a23c87bee9e39c09713c091be0e922a52cb4819cd5b8b2224a8655b294f563562bea20ae0260c0af9a337863e24184e081325cb7f6fb9af590f914268876387486772fd8228cfba1f3c04cae0878d1311137b4bcea0385359c96fa7e5456e209d1c4bfed0da1400e74db630b50e1f18340e2ddbda69ab8c6985773a4bdfde4c39cdb0f86bed2ca46600b9cd09f620356ef4005e67ecd3928f30464a4f56555052bdb5dfdda4589383ed3b10893263d44a11423d0e986549bd34a94c17b977ee18ec4de6ac0b807a22c7c52416d8559c132169d9df96fd6a30491aee7813d253b3869fca9d17f43301157f1198628428bec0427b066233620bd099bd2a500d1f8fe60a2ba185eaf344b8467f48bbab3b8ae127d00c63525b4076935c0d1ed2c37a9a2a9a52c5af466fc27c1e970ab3932ecc7a790985c08ea8238e2aacce14b8b11025e1702b92b95c5b7e54d77c74bbb1bd914bdfc85162921bca5bb22a3c037e3e74ff4a59de0f72592028d65520086131d362d7866659ee55c3818373a3eeb8aa5ddaafabaa02a4d72748e2dcb87be1ed198471e17d43ed382ab56d7ed0cd1808ea825ccfaa091c2b70f6b75dffa341169d106944c06f4d88d6b79ded94545d2dc455ba04b04cfa7fae50d2ad6e2344030bf08c37583645c5b24e3a0a75e3f9f899ac8bb32afc80e61d873d5a96aca05d9afde51549efbb7ef6b901929e1b752a4bc618fc19154d301a8f681bef774c10887ebe3b0387e4b38d272bdaaa35287efab7cc2d4308bfe0a7afedc728a16312b9216665998769b9d0508049299248d10ea5e43720545d6e76aa0180c641ec5356a52b3ab8d0522632b58acb9e84b184bfd9bf1cb097cfeb61b70cee781970233899a182228337d9153653acb91521f2048d7c0e784633a485c9efe97361fcf98af88eaf48bb25ad7117874487dc3754673558fe973b43a8f6b1cc9122af604f4a449ce529d9b8670b873c93b5ab968fb48798d671caf91e243edc80568f5cc05a0291075cda9e8efcf0c32f44fc4113d67488fd61d36c89a3b7ca71066242677cf695136d9258860bb4e627940ffbb708ad2e0d1653c84992384cfa836989345fa97d9b4ddac81e5d3441e49bc78b67d496be1fcd2110d8a8c16d10520cf2b4414abfeede7bda86ebd9e725c19234b6b80fe085370ede8f5d5abb1942d23269959f412c7e37e1fa4bfbb1e3fb4efa155f6619f30c9b8e2c996e8a2e71355212371929bac2674b4ed43860e0888d90cc22f35010518a58d8c5e03e2783e495f31531d1b1f5441cb7c656315ac2944ed4bb04bbcbaf7d0d03cb372ceaceda2337b19d8aa8afb5f2beafc08fef4a50de0e72c27e18ee3746402559a60341ec0d2dc16631b37f2e7997e8e60050c5a382220a7f5372dcd7d3b51d70f1cc70a8c7c412364f9bea9cbc6ce4e47c15d148c10215d6c3411f9d8b5e9ff5936c943e9a3e043cc06b26d5c13d6b2e731bd4ef5b99604d036db8b392856bbd51a99631a6bf75fead198c728eb7613cc1dfdbdba38af59b5c8237df92ef8eb1a859580d912ff8b275257de26e61e67784fb07623ef1dc4d02ac0d5917678a6d1de8ec617c32f2fb24fc6945d676cabf0ec7cc898723b91fcc72666885cc65b847990e17be6fa32c6b41ff29d1f86ae8169346a7d6a7423e3c50adb1a80157ecb3e952393879e21355b8f32128803091f4a97411b42ca19a763c1f296825c69e8bd1a3245d8a4e7633c78b60c9c17e4745eaa5ca549c83cacfd4c2a75899c5662127e960e6ac641265c91e1fa5b56c47d6c2bea6c2484bcc6a83c04d203b2a6eba30fe9e4029a49bb50f434a2b3b4b5a81fa31082ee2be601afc9b285038e7094770a154f2f75ce6962b005c19af69ca3de6898004a3e22d8c9524bba74084050ed0e59d9489c6cb1873419c837a106e27ac6097e61828f03c598a679bce03f3f8d7b171b0904545e4b77157840a2f6732fd9fe449e8df81fdd2b4ee5ee023500d87cac99b2c37011d93ed1cb6438e42fe35814b20cd5395809b52bceb86adfe9c61d117b350de4972852f00417666f264698ba96ccb9d7209b94cd4b803a81cea55f644646c2cef79c5f7b1a253e5889e1227a272cd08d110dbd4933fe786c04aa03c77d94b35a62ca5e32819ff5e43f3357d4f7170572d598a0f24f7762dce8e0304d4e39c45d475c28b30ea7c461977fbe330c5590bb3f99ebb3490b0d0f06c5068ff8ba11fc7080a248fa0250f281ec35086cb0cbb8ed205af98b629a05024949fc0c01abf475f89c999717e25a55dc342c40c9608510931474405b456e56b93290be973999d9d3fc7a7e97261bc71e27e1ee312d9f3f01fa50d839e2866b7ad7e98f7b026e0959696a2c06a4b6e21f53c38f479f34a780f2c26f0ef25970c63648d43268dad9efeca9569d7cd0db4f06cc5101f988ab88deb511578fde2e484400765ba60b1f8232db157542f1b8377ac7241ebed09d94f744492378aef16027a04f3ad7b3415f97bcedc0a2fc431fa3f7a1696199a9e6dfc880c592d453f0ef195a093f53b5b4e9bcf4412308e59e3ac4c7cb1cedc3759ad7f6df735471a7f9b185861d3f7d472c52fd675d3112719dbce80e516ad74c816bda6ddcb0000450092aafbbad8353bfe0c7b6361a741d6375f975681634eeff60444091f1861d7840c047db600e7ae09d3f3345a76a5b2f1571336e4784a63ecfd5d84cdc6be32d623bf46a952fe6a344740d874030ea44c7888dd8cc3a8af44426e93318b78c5a070a5c95eb68a7ab17b1803cb17a882a759e83aac4aa781fc4d1d3b6dc9bd3e61963eb7c629e7ea6bfc3cfdc9b96f3721aea846d27442f532cd990e9b4e1a34aec27ed2305384f51a4b8556da808c0c75e9b39cc5ebdc55d0eb2ac5e1b54455c32f2a464c82f41f2f01464ef1bdf2d3707155f120568d3b3d77b3c00f77386bf9cfe9c78cd48441d40563ec33b2294d25d87544d4e2a06efff753f272eaf2633faf4c30fe694f0d25521519102fa985a8ba13e6d704f3b8f496d5a91aa2f0a6ed3d4b84be7c2980feb7020ac6b1aed1477e351c1c0f8716679c36f77a67773b42fd25e16c58d65118ee8dde59e4fbff473d94172ef5acc4983c891b9fe1fcdfc254118fa937d1df16f6554d8630a1ed67712ba114afe09b02a24e8d28088eec997f7ecdae263761f22e1f3320c6a7af573b7e5155ec2cab6a10481a2e7e0dcf70f03ffd1c404f33e7c11228f87fad4daf04fb74cfe85f1f2d09316048989af5e02659a3179028f024dafb3ac078dc08fb4942c55a0598a23bc27a17acabe60bf2c9b055bcbacc0d6606a43a8921a9562420ac9031833854e35c437f47109b0349f4567dfa217b2fe73616aeb2adca404759e17a2f9a8ab013a89dce0fe2924c75f1409d5b0d1dd6e681b62f3805347734e644fcd3e4a7f8f2933b9d91d78ecf6db66ed711cec2f30559878e92dae7319d1de97c68837b119b8453004d88c07aa9e1138707edde7f9d10cfcc65f8132c5d5d9ff0859bcc4ae5825e001815b75b822b7c2c976e8c2af9e3a5e283c4ecd6467ca22ba32ae3da35e73178376573b4d75be7bc1a61c9ab7006726c6164e03f4b86fc724881347e358601f6bde536483660f4f39e1b90555e82b02ff6cfe3ecc3ed8778ce4fe7c843acbb3923858fceec096f6b22d5088c0ebc3482348050cbf30a749c5dc1e39feef13d2f564863c34faedb3ec590b5584ab72783becd0e3caa52a9fbeab8e30c450380fcb28e5f063623293fbd8d4dcc339acfc4654a141a45be2dc17af2c58c160505195803acf7286e67991710f20175175f23c992734af6e01dfbb8e1aae72376cbbadd43cf33d0dfb2c04c12c6cb7e04a0dc3867c0b246efc46903685700725c25319612101992c072de7719a4eccd8e16054644e07f24855cfedb24f7ca6fe86f13e1fa7abed1761ca5b405936562665c74f15aa98b0dfd83d6a05b944ad26faeda5f7919e03913caeaa14dcb6e2d3b0aa5ce3332fb824f221776a9e26bf50da18c55b4ae73e487af69698ca5e94d972c1e4c1d534d92bcfa03fa88d496eb3d53049d2bbc958b7c49fe24e9c4c887c76b1a0c70f75d2f9113e23acb1b4fbc7dba4b942adb1c8aeafac9b753488140f225d306bda6aba9482a8b5525ad4a70bcf638022c254ec0a630200032f6af79042ac9fdb5a7384752706553467f631286d9e3a7f9b17e87947dff99c4de3c74b7d87368829f9d4e4a9c56ffba32557c3e9adde7d311db1dac6bfe496a879bf4f6ca1337bdd4b0f4152b69afecdcbd4ec37078f12f7a5d9a2228ff981fd4e10603300000000000000014513d5002f1d393b76c3676afe7fdd5e4de5f9556e4eb61a3d77f17c463a65971b3710414307868f3ab1599a55e54da3c655f508c20f561e6f7c5015ad96c9daa1d71ada32b3aaa3049f6b08ec711ac8ed4cf934e938637aff3e06b1209d559bf396e31e37546b18b0aeec50d0a99097e6e54bc6d13a02355a5a16ae6196321f659cc5d7de0f27b142903b7acf6e9680e1f6f46c1081539958caa4a63f98a990e460b7ed58b81d4d03046558fd97ccf6241f33cd2cb09dbb628f0deab986ee8b8d7db7d80e65577c69def1d764d914c8fe40eae52a68ffbb5f0ef3d87fa4467bed76ec8f4068afc4d976d468571542439f2c3dadc13837d847611895c517d90ca77ad97162375d187d9760210e3777ca84a61a110e04cc0f0d1140f9da3d7e1d04f00bde64674cfe5d72f52d457e34b778b0a60453b6c5ad8b0c0602885078804d6b308dc206ba1e4d80e524a01aec1b58ea1435926b5b8cbfacbb9ed9737c76ea16b7f043faad4d1be4bf9cee0c0e89dcbd928df5f809b9387eb448b13d6066cdd5456997a37273895720f54b3b34376779ad40085e6bb6e7e816f301e4d2c184d814a378b16c37a23947704fbf56007d8291f99b2c7cc2faa20d213def429f9eac82e40ea1383f1a49e4d46831e26b6fb4a267b1d62f5999bf6973cabb9fb26c5bc0d5518f651277411e2c87b17e1417e0c6f96286a24f4b6f49f86fa7606241e92dd74a7d4dccd2b918aa8d97339fde050abec8276d1b5c9e16b40673a54d5fefd5936553a8d89704fd09b95ae3e566f1c4436c8c22a268962120a5e1676335984f0e876be550cbac818c4d6f630618b37c8089bdd919d505e3ffc1f5b82603c3db0ef6e846fbfedcdce9e70e6acf39ab79b85590e9130c52a1e1ed190936dd5b440fa984b1905049e1809228fea9b8b4748d89345327727875f29991faaa24d566d4621cd5533a1428eed87a7783e22343e1ce2e44f4b58d67461f123cd2f86dec7fe3878772238487c7ec1e70288566e755c6b8736643c3429af82e7543cd96e214b47b25a12cd05e0997af75edad3fff7ac2258424a46c442dd629845cf65219013a9ba00b0544f3c91fd784fd810dd1fc8cbcca490eea042493c6703732ca8b75925f78692184cf162f0c287cb2fffef9ef9e66534ddade0b2fd2abccaabd8acdfe92f2447f81845b2dcb5543604747d19d9c0a8a2642fc912f1f9b892505a4bcbf26e9474cda119b3c0928b01f1f6e79fef034a25ef3bc4493a0f5f860b31b5e8f513b2707804aa43a97d96ccdc872131305aa5532fc9db1e0acf765f9d86780901c0061d10177a2cbfd867c1438cf9c05038f107b53d3d844f084ae7a968a4132442569d217d8babd6307c926cad9197dbc329fe060c75839a332927a4c25215dd030f322c0b8772969687f87096965f7d229459ba13673e4b51a9400ed0f08fedbb775875a383852471548ebd673555e39bcd45c4b1fd2f7bf8816bd998880b4aa699655f1998974abbee5abd595a2a2e8dc6988f5d388ec7735a6758b01974bae2ea1ffce024dcd7ee7b5419cbbd7eaa7ca94893ec0b814f4ef893b6205aec6e7d6dffe9886b8bd43051b17b6d2e3cae515e2b632c4e165b761984ebaa3cc63e8483149120b9eccb504d21cd1360ddcd2530795b1182b458dc4108caf3589f9e021e378e9e62cd6dc669c622127c3483ee52f854c3dca27747be8a263f03207b616d4001056050c99a6835f638204f16bca4440916bc528f01bf76749908cb1a2dbb312fbf7eab2b2fadff6c4bcf617ec710a89facf524a6e3351a0ae1839aaf314e3a22852d0af445e4faaf94a61590576a56c55c0f6b5e2bce9fca565b5dd8f4392cd95f955ffe42c94c6cc647cceea8b7701befd14f291e42e68aeccf1bc3c1360c26ab5dab9aa6ecc7fd959d3aa5272e1038ebbe8bee672d015df29837d1bd2d206a75c1e0e9859043a75c0b53706dd8216a0878e17a38929646d9901106c2bca5ad898759eac4580b50a956edec803c8eb7efca6bf0bfc5949265162fc163847e986797981f99a325edbc501abc7f9fc831c09eb03b0aa8b324ef564a96867862f7b9872f09da4e99d46acd25b99ab752e2d66de1c7c84472df94bd35c157339cbcc4adc9fc3e8fb5d1074bcc8d2a6fdd61d2c14b920c733e1a7bb31fc5b4fc528bd1a3109fa72a57f20581d951e81fdcff50f1ed2bc0353d2d9c2d2dcc9ee0c90b3c7cd4191a31514cafe9d61581335c292ab841350b5d9259877c211bac26b710df47edcd614de762187691120b3b9e81e14b5832bf072cb8e9d2d83824804fb83fdc6622988f392ac3da3099a73ef266b251bc7eaf35bdce13d20da8143ff84f0f0b9b1852ed0fa185a380afe51528a8c77eccd61899623352d266294c5671bb2d9a9a667d345188c48e16b2b5ecd30de3a1ca85f14f135500cbd804be24eb89561d52708de308659a40c40c3f8e3563db8352c3902604dc818ea86bd49c0c31404fd0ac023f3c65e4c206a45b6f0d28036e01de7cee09d3088eca85f876c2318c463df70a34b2f1bb00de9ff3b1100497bad8027d1759edbc3ffa70d58ca6d863cb2ecbe503044e3d1d05881a5b36615417b3fdff0ddcc339e53c0b036d57eac050641f3d0bc6e515a56810aac3cd84d2aae5c7ba687e8140ae4931b8aa4afe54b11c131368c403f354465c079fe35140d0aff7b6d33ebed8d97c722a53bb5a7f9adfa0f89fdd36bace37a6edfce7b71a4b925c8f396023029a601b05fcf12111d308f83a8ebbd145c991d47828de347084734382c838ea6bd85cb4cee08e1486bab3a89105ac4a6c908e59f210382ac72394d8065764ab2f9ccb16efd1cbde4c537c83d5c2e0e366a512a1de79e646bcacdd565860d5939ef08453b791a6ae4b713ba33f329a90109dcc9e24cfcfe0e4db60083e1e23516ed1bab54402bda5f38d26b22e0e05ec43ce1193dd2bbb893231ea04f2092fb39d4aafc665c6ee939e9a71f67a010e42d67a8c2acf303ffa715353a8b634d83973676e392cd91f0e21e17a7b6f4a160ceb623ded40934313c6f885f0ee0449b14da2703fc66aab46fe22ac67bd3b3ce99fb839f93319274782f84fa73a3cb531243f04615a537bb48219a65a84e967fb0a7abf10c28141a3f0f15dfe1820f64e1d333ca773a6ac8b282b380db77a8359dbe435247483dfa3018f56da1f16dcc4c70bd16c1a5092682cdbf18cf4e1302637e9998170728941448ef25d7e3bacc8b144f3d0251efec6dc362a680ddaeda5cb619ecafb7d887269f1a4b226d493fa5c5f3120fd084f92282c508aa46740e1d4353f52cd9e71ce5fac8359157d0ddb5c552d628a373d9c8fc2547ba64cb6074422d8ff271ee4eecd6012edcdbdac2389d39444c21ef0b257690370a5fdb53a7ef6bd80eff4066b8c1e05f2c2e80767b40108c51f74aec210f9ea0ec4d7571d8dc8c6828c9582cf6da80e35c0aee3ed1c839011b18ae434a07fa71fbf433dc13bf76e93e0437ade514ba56e5b505e185e4a4c0dc72a526f7ed123bb127e18c02badacf18beaf9530007f026623e8204130028b7906cd2c26ec2b0186f0eb9b23bce74d3c6bfa2609d5db5e7b705816cdad21b27199e762785b1bb7971dff9283b5edf95424b397bd532bd1e809cc4deecff6f2336c39fb073f49f0b3aecc9a5edee41ab6ee95c9efb565662eeabf2334ac4b457c29394d6354c57147df973cf691d0f3de19d97afa97a057b41d1f1f1fb12629324c75765a815b7d843b8621f60085afaa9fad4fe5f505859ad3ae96af566518c3b1b28d94a08e429fef467bc3f6cc7b68891ed57580130cfbcca5d38c6aa9807b960a0936f12de587c64a9b7cbf8ed565a7cf6e9ec3cc7377974fea6aab4d1a67ef19f29cf9a45a9d93078b57a8021c6a88106119940110b9dd205f59ce7696094fdf848982cbfc58c2cf9807d37da5ff7f08368952d37ce27228866356743c0e3885caf74d4b7d6d89a278c529d06e7946ed3b5d599c44569c477b3bdf5a4d7f8b9a3770121c43d7c3bb3f37dd920d5b77c0ee15074516dd575c43e3630256db31f07987d691d2b4b18762440ae4ed574331bdbafd690d794c5e0c24ae628a1480b6b1882e1fcbcec2eabea3c0d249341bc6aa5cc71df7360ac94410b368f8353d1bf0f9d544c6cc56b4a853f72fc9154c9e30c9797d899b5567b543aff9c82f198f932409bc0801bb502374c454f9def6a2012c28a687ddde82203c9f8d11c616f4dad2a8b6a4182732a93874fe6c1a3f31dc05d92f6a761315d99f68d447aa6538437d3f4a054f83a4db40b9588189f75cacb284bb208254a1d9098d54950b215aaa03bd1b7d5eb54f65ae532f89662fbb3924a74c412f9f862d25110446810ecda1a31a921292ecdf78e6d66f7bdc2bf7e15846853ae72bb6099dc486c34d366637020f9c61e4371977d9887f045e840c4aa42d5657114cf4b1369a6b78cee813f4e4be2700d8d1d6c29ccdde12e49ab1200877cc0973be950aaa6195633f55d386b161159738e922b4c06e5d068691c2f332235770492db8d082bde92385996c681c6950af4d231695b3a47618be5d25284e79b4d5d0a9fa425a88cda75eaacce12ca424c16be6bb4e162161cdad8fb19a8ad549950ac1c16f4a818610afadeedcad037f3caf46860ed742cc1ed3077c6093e282b3556c20d63fc1d27887a649afc9661912a53cdf7fd504bd4625dc0b3f4d1f8828e476db7a8a890ab2aa156fc75b163a2663a16ab7453d43e61adacb60d85d8bec4490d4951041a65c64bd4b5080b8e39230ffdbe86f2a9f162b26a8212f5bfa10d9a580aea0593056edacc98fc2db7d793ab471dfac036cfb54027c28f577b14aee0edeaa3e01935586994ff850dd7ae5e0682d1cd3c87f52933e9c0d6de823a9212e3a34056730f42ff801093a9e52d87ec100f69fb8e78585d338473c1482b462852f97d7583b0b1ced63de585b1a5f1e830f90547ab3587ffa2d3012010f17a8327c13a7c640878a22b427df2402e78a6e87cdcf6cc0e31c1892229568be5bb13068ce42fa8039b36dc5b1d414df2c5cfd8d66f69c0cb387ca3a3da1c855e35f7612ed8c5a768783dde4f65df3be09134be6b803addcb646bd182192d4a7b84c4f56c4cf1ef34cbe618685a470956886effefe84df16cb7df414af4c9a3cd621df78f1d5b9bb19e7c4b0d3656e37bfe977b7e8d4f8166ca3e9cff7dc29704ac1c953000a58848674bc68f6527d2c6fbdf936fb10f2ac3db0100495e52c203b4997f596d636d4bfa3efdfb5753c4d2866b4bbcf31e28bc8d919ca4eed461678aa2056ef94cc84707203ce2948beb395b1bf655c48221a3fb80508af183ef7ea3f715e2883d5f8e323a321b56ef3225df247fbd4807fb9f36780847d74ebc6c4015e3611a5bfc12ca3867daeb9342654e82e876c3235f52bd4b4fe6e96f579634e5b57e3c216ce415602ee1e3dcaaf2a6b91bbabaebb0ecf666169ec96defe03406c844069e2a6ad8cf4864e5b764afc82b26094c6077fa1e8dd689a80498642baa30eb9dda52ad0e7dd29f2e8c14de5a604079ca7383bcc87c21df441bd76a23b3a75a74283eec758896baf2cb417c83c7d1b39a7cf871170d1857f9656b0b593ac13998b2ae07687d7a804f5ade3bd2b40d9e5f9ab51560ff352a82a5bee219fdccd02b8677dbfe283d66ce8d02d8ef6faca8253ce8b9bdbde8f2cd0828e5bbb5b124a8e6a2dd07cac77cedbd08accb1d85a90fb10d01ec0dd8a9635100394341dfcbd923fa0110476548fb9b3499eb4f0a0275c509c074e692bf5260387eae8dcfe78a2913f95cc60605e82a904301c5764a71ddd9d92cebe20fb7cc974d926d90de18c78d90000";
        let tx: Transaction = deserialize(&Vec::<u8>::from_hex(&tx_hex).unwrap()).unwrap();

        let abfs_in = [
            "8987fdb72abbb9e267be82199a48ef532fb611399a459f5fae09894f2dc0af38",
            "110ac9e9b32a4c0bb7adfb4b1ddf6109265884c228e0d145ef22b9e9be679b52",
            "475523cfb711a46402da784a295fab089bcfa3e6bec7a5c9314c6f85ea867c5f",
        ];
        let abfs_in = abfs_in
            .iter()
            .map(|x| AssetBlindingFactor::from_str(x).unwrap())
            .collect::<Vec<_>>();
        let vbfs_in = [
            "3f8dc7822008d6a6a68e02427467a6491456fde62e0c7ce9644f334c6a73dfea",
            "3cb0b8d900c6594c6c070c487fd881b7d89700395766f48a8b663543c67c0388",
            "ea553ebf571bbd6dde5eb7d0820569aa1f105741057b03ae426f45ac7ff7da13",
        ];

        let assets_in = [
            "0d427836e46e919653de03f0820e41b223af045a560f677f9f7b0a4b49181688",
            "7ab4e27d079e798c516bbb8a401ecb996a6600f89407b7c8993fe5fa8b914018",
            "144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49",
        ];
        let assets_in = assets_in
            .iter()
            .map(|x| AssetId::from_str(x).unwrap())
            .collect::<Vec<_>>();
        let vbfs_in = vbfs_in
            .iter()
            .map(|x| ValueBlindingFactor::from_str(x).unwrap())
            .collect::<Vec<_>>();
        let values_in = [1u64, 1, 98567];

        let secp = Secp256k1::new();
        let mut utxos = [TxOut::default(), TxOut::default()];//, TxOut::default(), TxOut::default()];


        {
            utxos[0].asset = Asset::from_commitment(&Vec::<u8>::from_hex("0bdabc318c05dfc1f911bd7e4608ad75c75b3cc25b2fe98fa3966597ab9a0a473f").unwrap()).unwrap();
            utxos[1].asset = Asset::from_commitment(&Vec::<u8>::from_hex("0a7998b3be50dffa3d2d6b7483342fa7d806f642c6ee4fbbfb1e37c89a2e2cd97b").unwrap()).unwrap();
            // utxos[2].asset = Asset::from_commitment(&Vec::<u8>::from_hex("0ab51a141daccc447bd9776dcd7b7995da21d7b19c65fdb2212e3d1c6109c43e3e").unwrap()).unwrap();
            // utxos[3].asset = Asset::from_commitment(&Vec::<u8>::from_hex("0bd56b8ccdea532b46000edfc96a41461c4a58eaa6fb5d2af8ae65fec3e1916652").unwrap()).unwrap();

            utxos[0].value = Value::from_commitment(&Vec::<u8>::from_hex("08fb70255ab047990780c71fed7b874ca4ece6583ade26b37bf7d7f1c9284f4c84").unwrap()).unwrap();
            // utxos[0].value = Value::Explicit(1);
            // utxos[1].value = Value::Explicit(1);
            utxos[1].value = Value::from_commitment(&Vec::<u8>::from_hex("096001a872e3672f9daaa19cf5b54a807ee9650012d9245d5e61ef27327a53a3ad").unwrap()).unwrap();
            // utxos[2].value = Value::from_commitment(&Vec::<u8>::from_hex("0864d03cef7dd7ffe6c3124ed1f05dbd55c4e3b0b2aeb24f41daf91201d03ae38d").unwrap()).unwrap();
            // utxos[3].value = Value::from_commitment(&Vec::<u8>::from_hex("095c5b4cc49d1621e5fa2167e1e2c54caf05285e53fcf3020d7014d48b7880eb57").unwrap()).unwrap();
        }
        tx.verify_tx_amt_proofs(&secp, &utxos).unwrap()
    }
}
