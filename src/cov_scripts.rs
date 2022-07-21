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
    CovenantExt, Descriptor, DescriptorPublicKey, Tap, TranslatePk, Translator,
};

use crate::{contract::OptionsContract, UserCovType};

/// type alias for miniscript with Tap script Ms with extensions
type MsTap = miniscript::Miniscript<XOnlyPublicKey, Tap, CovenantExt<CovExtArgs>>;
/// type alias for taproot descriptor for extensions
pub(crate) type TrDesc = Tr<XOnlyPublicKey, CovenantExt<CovExtArgs>>;

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

/// Translate the given Tr descriptor to Descriptor<DescriptorPublicKey>
pub(crate) fn translate_xpk_desc_pubkey(desc: TrDesc) -> Descriptor<DescriptorPublicKey> {
    pub struct DummyTranslator;

    impl Translator<XOnlyPublicKey, DescriptorPublicKey, ()> for DummyTranslator {
        fn pk(&mut self, pk: &XOnlyPublicKey) -> Result<DescriptorPublicKey, ()> {
            Ok(DescriptorPublicKey::Single(SinglePub {
                origin: None,
                key: SinglePubKey::XOnly(*pk),
            }))
        }

        fn pkh(
            &mut self,
            _pkh: &<XOnlyPublicKey as miniscript::MiniscriptKey>::Hash,
        ) -> Result<<DescriptorPublicKey as miniscript::MiniscriptKey>::Hash, ()> {
            unreachable!("No Pkh in descriptors")
        }

        fn sha256(
            &mut self,
            sha256: &<XOnlyPublicKey as miniscript::MiniscriptKey>::Sha256,
        ) -> Result<<DescriptorPublicKey as miniscript::MiniscriptKey>::Sha256, ()> {
            Ok(*sha256)
        }
    }
    let desc = Descriptor::TrExt(desc);
    desc.translate_pk(&mut DummyTranslator).unwrap()
}

#[cfg(test)]
mod tests {

    use crate::BaseParams;

    use super::*;
    use miniscript::elements::{taproot::LeafVersion, AddressParams, OutPoint, Txid};
    use std::str::FromStr;

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
}
