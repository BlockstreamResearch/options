//! Create a call option on Elements
use std::str::FromStr;

use elements::encode::Encodable;
use elements::hashes::HashEngine;
use miniscript::bitcoin::{self, XOnlyPublicKey};
use miniscript::elements::confidential::{AssetBlindingFactor, ValueBlindingFactor};
use miniscript::elements::hashes::{sha256, Hash};
use miniscript::elements::secp256k1_zkp::{Secp256k1, Signing};
use miniscript::elements::{confidential, Address, AssetId, ContractHash, OutPoint, TxOut};

/// The high level user parameters to the options contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(crate::serde::Serialize, crate::serde::Deserialize)
)]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct BaseParams {
    /// The contract size in sats per contract. 1M sat per contract
    pub contract_size: u64,
    /// The timestamp represented as bitcoin tx `nLockTime`
    pub expiry: u32,
    /// The start date of the contract
    pub start: u32,
    /// The strike price
    pub strike_price: u64,
    /// The collateral asset id
    pub coll_asset: AssetId,
    /// The settlement asset id
    pub settle_asset: AssetId,
}

impl BaseParams {
    /// Add the information of BaseParams to HashEngine
    fn id(&self, mut engine: &mut sha256::HashEngine) {
        self.contract_size.consensus_encode(&mut engine).unwrap();
        self.expiry.consensus_encode(&mut engine).unwrap();
        self.start.consensus_encode(&mut engine).unwrap();
        self.strike_price.consensus_encode(&mut engine).unwrap();
        self.coll_asset.consensus_encode(&mut engine).unwrap();
        self.settle_asset.consensus_encode(&mut engine).unwrap();
    }
}

/// Tokens required for claiming associated assets
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(crate::serde::Serialize, crate::serde::Deserialize)
)]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct OptionsContract {
    /// Crt re-issuance token
    crt_rt: AssetId,
    /// Ort re-issuance token
    ort_rt: AssetId,
    /// The collateral rights token asset id
    crt: AssetId,
    /// The Options rights token asset id
    ort: AssetId,
    /// Crt re-issuance asset entropy (Required while re-issuing assets)
    crt_reissue_entropy: sha256::Midstate,
    /// Ort re-issuance asset entropy (Required while re-issuing assets)
    ort_reissue_entropy: sha256::Midstate,
    /// Unspendable key
    unspend_key: XOnlyPublicKey,
    /// The config for this contract
    params: BaseParams,
}

/// Returns the [`ContractHash`] used in this contract
/// This can be used as a versioning system across multiple updates to this contract
pub fn draft_contract_hash() -> ContractHash {
    ContractHash::hash("elements-options-draft-v0".as_bytes())
}

impl OptionsContract {
    /// Creates a new [`OptionsContract`].
    pub fn new(params: BaseParams, crt_prevout: OutPoint, ort_prevout: OutPoint) -> Self {
        // Versioning incase we want to update the scripts
        let contract_hash = draft_contract_hash();
        let (crt_reissue_entropy, crt, crt_rt) =
            new_issuance(crt_prevout, contract_hash, /*confidential*/ false);
        let (ort_reissue_entropy, ort, ort_rt) =
            new_issuance(ort_prevout, contract_hash, /*confidential*/ false);
        // unspendable key = lift_x(Hash(ser(G)))
        let unspend_key = bitcoin::XOnlyPublicKey::from_str(
            "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0",
        )
        .unwrap();
        Self {
            crt_rt,
            ort_rt,
            crt,
            ort,
            crt_reissue_entropy,
            ort_reissue_entropy,
            unspend_key,
            params,
        }
    }

    // Helper function to return an array of blinded assets where the first element
    // is blinded with blinding factor one and the second is blinded with blinding factor two
    // Returns a pair [(conf_asset_a, abf_a), (conf_asset_b, abf_b)]
    fn asset_rt_blinds<C: Signing>(
        &self,
        secp: &Secp256k1<C>,
        asset: AssetId,
    ) -> [(confidential::Asset, AssetBlindingFactor); 2] {
        let one = AssetBlindingFactor::one();
        let two = AssetBlindingFactor::two();
        // Compute blinded asset for ort_rt
        let blinded_a = confidential::Asset::new_confidential(secp, asset, one);
        let blinded_b = confidential::Asset::new_confidential(secp, asset, two);
        [(blinded_a, one), (blinded_b, two)]
    }

    /// Returns the possible ORT RT blinded assets
    /// According to elements consensus rules, we have the following constraints:
    ///     - Issuing asset must be blinded
    ///     - Any confidential output asset cannot be equal to confidential input asset
    /// To avoid this we need to cycle the RT tokens between two fixed blinded assets. `blindedA` spends to `blindedB` and vice versa.
    /// The asset blinding factors for creating these are fixed values known beforehand.
    pub fn crt_rt_blinds<C: Signing>(
        &self,
        secp: &Secp256k1<C>,
    ) -> [(confidential::Asset, AssetBlindingFactor); 2] {
        self.asset_rt_blinds(secp, self.crt_rt)
    }

    /// Similar to [`OptionsContract::crt_rt_blinds`], but for ort rt
    pub fn ort_rt_blinds<C: Signing>(
        &self,
        secp: &Secp256k1<C>,
    ) -> [(confidential::Asset, AssetBlindingFactor); 2] {
        self.asset_rt_blinds(secp, self.ort_rt)
    }

    /// Returns the ort rt of this [`OptionsContract`].
    pub fn ort_rt(&self) -> AssetId {
        self.ort_rt
    }

    /// Returns the crt rt of this [`OptionsContract`].
    pub fn crt_rt(&self) -> AssetId {
        self.crt_rt
    }

    /// Returns the ort of this [`OptionsContract`].
    pub fn ort(&self) -> AssetId {
        self.ort
    }

    /// Returns the crt of this [`OptionsContract`].
    pub fn crt(&self) -> AssetId {
        self.crt
    }

    /// Returns the params of this [`OptionsContract`].
    pub fn params(&self) -> BaseParams {
        self.params
    }

    /// Returns the unspend key of this [`OptionsContract`].
    pub fn unspend_key(&self) -> XOnlyPublicKey {
        self.unspend_key
    }

    /// Returns the crt reissue entropy of this [`OptionsContract`].
    /// Required while re-issuing assets
    pub fn crt_reissue_entropy(&self) -> sha256::Midstate {
        self.crt_reissue_entropy
    }

    /// Returns the ort reissue entropy of this [`OptionsContract`].
    /// Required while re-issuing assets
    pub fn ort_reissue_entropy(&self) -> sha256::Midstate {
        self.ort_reissue_entropy
    }

    /// Returns the contract hash of this [`OptionsContract`].
    pub fn id(&self) -> sha256::Hash {
        let mut engine = sha256::Hash::engine();
        self.params.id(&mut engine);
        engine.input(&self.crt_rt.into_inner());
        engine.input(&self.ort_rt.into_inner());
        engine.input(&self.crt.into_inner());
        engine.input(&self.ort.into_inner());
        sha256::Hash::from_engine(engine)
    }
}

/// Parameters to be used when funding a new options contract
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct FundingParams {
    /// The crt prevout along with the txout
    pub crt_prevout: (OutPoint, TxOut),
    /// The ort prevout along with
    pub ort_prevout: (OutPoint, TxOut),
    /// The number of contracts to fund
    pub num_contracts: u64,
    /// Crt destination address
    pub crt_dest_addr: Address,
    /// Ort destination address
    pub ort_dest_addr: Address,
}

/// Parameters to be used for all user-facing covenant operations.
/// In case of expiry/cancel/exercise, the cov_prevout should be collateral
/// covenant prevout. In case of settlement covenant, the cov_prevout should
/// be the settlement covenant
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct CovUserParams {
    /// The prevout along with the txout
    pub cov_prevout: (OutPoint, TxOut),
    /// The number of contracts to exercise
    pub num_contracts: u64,
    /// Destination address for collateral/settlement
    pub dest_addr: Address,
}

/// Returns a tuple:
/// - The asset ID when issuing asset from issuing input and contract hash
/// - The re-issuance token from input and contract hash
// TODO: PR all of these to rust-elements
fn new_issuance(
    prevout: OutPoint,
    contract_hash: ContractHash,
    confidential: bool,
) -> (sha256::Midstate, AssetId, AssetId) {
    let entropy = AssetId::generate_asset_entropy(prevout, contract_hash);
    (
        entropy,
        AssetId::from_entropy(entropy),
        AssetId::reissuance_token_from_entropy(entropy, confidential),
    )
}

/// Implementations of fixed constants for [`AssetBlindingFactor`]
pub trait Consts {
    /// Returns the abf corresponding to scalar 1
    fn one() -> Self;

    /// Returns the abf corresponding to scalar 2
    fn two() -> Self;
}

impl Consts for AssetBlindingFactor {
    fn one() -> Self {
        let mut one = [0u8; 32];
        one[31] = 1;
        AssetBlindingFactor::from_slice(&one).expect("Valid scalar")
    }

    fn two() -> Self {
        let mut two = [0u8; 32];
        two[31] = 2;
        AssetBlindingFactor::from_slice(&two).expect("Valid scalar")
    }
}

impl Consts for ValueBlindingFactor {
    fn one() -> Self {
        let mut one = [0u8; 32];
        one[31] = 1;
        ValueBlindingFactor::from_slice(&one).expect("Valid scalar")
    }

    fn two() -> Self {
        let mut two = [0u8; 32];
        two[31] = 2;
        ValueBlindingFactor::from_slice(&two).expect("Valid scalar")
    }
}

/// Converts an asset blinding factor to value blinding factor
pub fn abf_to_vbf(a: AssetBlindingFactor) -> ValueBlindingFactor {
    ValueBlindingFactor::from_slice(a.into_inner().as_ref()).unwrap()
}
