//! Create Call-Put options on elements
//!
// Coding conventions
#![forbid(unsafe_code)]
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![deny(dead_code)]
#![deny(unused_imports)]
#![deny(missing_docs)]
#![deny(unused_must_use)]

extern crate elements_miniscript as miniscript;

pub mod contract;
pub mod cov_scripts;
use std::{error::Error, fmt};

use contract::AbfConsts;
pub use contract::{BaseParams, OptionsContract};
pub use miniscript::elements::pset;
pub use miniscript::elements::pset::PartiallySignedTransaction as Pset;
use miniscript::{
    bitcoin,
    elements::{
        confidential::{self, AssetBlindingFactor, ValueBlindingFactor},
        hashes::{sha256, Hash},
        secp256k1_zkp::{
            self as secp256k1,
            rand::{CryptoRng, RngCore},
            All, Generator, RangeProof, Secp256k1, Signing, SurjectionProof, Tag, Tweak,
            ZERO_TWEAK,
        },
        AssetId, ContractHash, OutPoint, TxOut, TxOutSecrets, TxOutWitness,
    },
};

use crate::contract::draft_contract_hash;

/// Trait for adding options contract support for Pset
pub trait OptionsExt {
    /// Initialize the option contract by creating a pair of re-issuance tokens
    /// sent to the address bound by the RT covenant.
    /// Mutates the pset by adding re-issuance inputs/outputs and blinding it.
    ///
    /// Unfortunately, due a bug in elements wallet, this will produce incorrect signatures in
    /// walletprocesspsbt. Therefore, you can sign with
    /// `signrawtransactionwithwallet` after extracting it using [`Pset::extract_tx`]
    ///
    /// # Precondition:
    ///
    /// - Unblinded balanced pset with atleast two(possibly confidential) bitcoin inputs and two outputs.
    /// - The first output must be the destination output for bitcoin. The user must supply
    /// the receiver blinding key for this output. In other words, this must be confidential
    /// - The second output must be the fees. The fees should account for the one tx rangeproof, and two
    /// issued outputs with surjection proofs.
    ///
    /// # Arguments:
    ///
    /// * `params`: The [`BaseParams`] defining this options contract
    /// *`txout_secrets` : The [`TxOutSecrets`] for each input
    ///
    /// # Returns:
    ///
    /// - The [OptionsContract] data structure to be used creating/interacting with options contract.
    fn issue_rts<R: RngCore + CryptoRng>(
        &mut self,
        secp: &Secp256k1<secp256k1::All>,
        rng: &mut R,
        params: BaseParams,
        txout_secrets: &[TxOutSecrets],
    ) -> Result<OptionsContract, InitError>;
}

impl OptionsExt for Pset {
    fn issue_rts<R: RngCore + CryptoRng>(
        &mut self,
        secp: &Secp256k1<secp256k1::All>,
        rng: &mut R,
        params: BaseParams,
        txout_secrets: &[TxOutSecrets],
    ) -> Result<OptionsContract, InitError> {
        // Check that there are atleast two inputs
        if self.inputs().len() < 2 {
            return Err(InitError::AtleastTwoInputs);
        }

        if txout_secrets.len() != self.inputs().len() {
            return Err(InitError::UtxoSecretLenMismatch);
        }

        let crt_inp = &self.inputs()[0];
        let ort_inp = &self.inputs()[1];

        let crt_prevout = OutPoint {
            txid: crt_inp.previous_txid,
            vout: crt_inp.previous_output_index,
        };
        let ort_prevout = OutPoint {
            txid: ort_inp.previous_txid,
            vout: ort_inp.previous_output_index,
        };

        let (fund_desc, contract) = params.funding_desc(secp, crt_prevout, ort_prevout);
        let dest_spk = fund_desc.script_pubkey();

        // To avoid dedup for repeated code for ort/crt assets.
        let arr = [(0, contract.crt_rt()), (1, contract.ort_rt())];

        // Add issuance information with one explicit value
        // Create tokens with 0 asset amount and 1 token amount
        for i in 0..arr.len() {
            self.inputs_mut()[i].issuance_value_amount = None;
            self.inputs_mut()[i].issuance_inflation_keys = Some(1);
            self.inputs_mut()[i].issuance_asset_entropy = Some(draft_contract_hash().into_inner());
        }

        for (i, asset_id) in arr {
            // Check that inputs don't already have an issuance
            if self.inputs()[i].has_issuance() {
                return Err(InitError::IssuancePresent(i));
            }

            let domain = surjection_inputs(&self, secp, txout_secrets)?;
            let out_tag = asset_id.into_tag();
            let out_abf = AssetBlindingFactor::one();

            let prf = SurjectionProof::new(secp, rng, out_tag, out_abf.into_inner(), &domain);
            let prf = prf.map_err(|e| InitError::Secp(e))?;

            let txout = TxOut {
                asset: confidential::Asset::new_confidential(secp, asset_id, out_abf),
                value: confidential::Value::Explicit(1),
                nonce: confidential::Nonce::Null,
                script_pubkey: dest_spk.clone(),
                witness: TxOutWitness {
                    surjection_proof: Some(Box::new(prf)),
                    rangeproof: None,
                },
            };
            self.add_output(pset::Output::from_txout(txout));
        }
        custom_blind_tx(self, secp, rng, txout_secrets)?;
        Ok(contract)
    }
}

// The in-built blinding APIs are not help because
// 1) elementds always blinds pset issuances. There is no way to set
// that we don't need blinding for issunaces
// 2) Doing partial blinding without considering issuances makes it harder
// to balance out the surjection/rangeproofs.
fn custom_blind_tx<R: RngCore + CryptoRng>(
    pset: &mut Pset,
    secp: &Secp256k1<All>,
    rng: &mut R,
    utxo_sec: &[TxOutSecrets],
) -> Result<(), InitError> {
    let surjection_inputs = surjection_inputs(pset, &secp, utxo_sec)?;
    let mut inp_v_secrets = vec![];
    for (i, inp) in pset.inputs().iter().enumerate() {
        inp_v_secrets.push((
            utxo_sec[i].value,
            utxo_sec[i].asset_bf,
            utxo_sec[i].value_bf,
        ));

        if inp.has_issuance() {
            inp_v_secrets.push((1, AssetBlindingFactor::zero(), ValueBlindingFactor::zero()));
        }
    }

    // blind the last txout
    let out = &pset.outputs()[0];
    let asset = out.asset.ok_or(InitError::BlindConfAsset(0))?;
    let value = out.amount.ok_or(InitError::BlindConfValue(0))?;
    let out_abf = AssetBlindingFactor::new(rng);
    let out_asset = confidential::Asset::new_confidential(&secp, asset, out_abf);
    let out_asset_commitment = out_asset.commitment().expect("confidential asset");

    // Balance the equation for the last blinding factor
    let mut exp_out_secrets = vec![];
    for (i, out) in pset.outputs().iter().enumerate() {
        if out.blinding_key.is_none() {
            let amt = out.amount.ok_or(InitError::BlindConfValue(i))?;
            // Outputs two and three are crt/ort rt outputs. Initially they use one asset blinding factor
            let abf = if i == 2 || i == 3 {
                AssetBlindingFactor::one()
            } else {
                AssetBlindingFactor::zero()
            };
            exp_out_secrets.push((amt, abf, ValueBlindingFactor::zero()));
        }
    }
    let final_vbf =
        ValueBlindingFactor::last(&secp, value, out_abf, &inp_v_secrets, &exp_out_secrets);

    let value_commitment =
        confidential::Value::new_confidential(&secp, value, out_asset_commitment, final_vbf);

    let value_commitment = value_commitment.commitment().expect("confidential value");

    let receiver_blinding_pk = &pset.outputs()[0]
        .blinding_key
        .ok_or(InitError::BlindingKeyAbsent(0))?;
    let (nonce, shared_secret) =
        confidential::Nonce::new_confidential(rng, &secp, &receiver_blinding_pk.inner);

    let message = RangeProofMessage { asset, bf: out_abf };
    let rangeproof = RangeProof::new(
        &secp,
        RANGEPROOF_MIN_VALUE,
        value_commitment,
        value,
        final_vbf.into_inner(),
        &message.to_bytes(),
        pset.outputs()[0].script_pubkey.as_bytes().as_ref(),
        shared_secret,
        RANGEPROOF_EXP_SHIFT,
        RANGEPROOF_MIN_PRIV_BITS,
        out_asset_commitment,
    )
    .map_err(InitError::Secp)?;

    let surjection_proof = SurjectionProof::new(
        &secp,
        rng,
        asset.into_tag(),
        out_abf.into_inner(),
        surjection_inputs.as_ref(),
    )
    .map_err(InitError::Secp)?;

    // mutate the pset
    {
        pset.outputs_mut()[0].value_rangeproof = Some(Box::new(rangeproof));
        pset.outputs_mut()[0].asset_surjection_proof = Some(Box::new(surjection_proof));
        pset.outputs_mut()[0].amount_comm = Some(value_commitment);
        pset.outputs_mut()[0].asset_comm = Some(out_asset_commitment);
        pset.outputs_mut()[0].amount = None; // Reset to none so that we don't have to provide blinding proof
        pset.outputs_mut()[0].asset = None; // Reset to none so that we don't have to provide blinding proof
        pset.outputs_mut()[0].ecdh_pubkey = nonce.commitment().map(|pk| bitcoin::PublicKey {
            inner: pk,
            compressed: true,
        });
    }
    Ok(())
}

pub(crate) struct RangeProofMessage {
    pub(crate) asset: AssetId,
    pub(crate) bf: AssetBlindingFactor,
}

impl RangeProofMessage {
    pub(crate) fn to_bytes(&self) -> [u8; 64] {
        let mut message = [0u8; 64];

        message[..32].copy_from_slice(self.asset.into_tag().as_ref());
        message[32..].copy_from_slice(self.bf.into_inner().as_ref());

        message
    }
}

pub(crate) const RANGEPROOF_MIN_VALUE: u64 = 1;
pub(crate) const RANGEPROOF_EXP_SHIFT: i32 = 0;
pub(crate) const RANGEPROOF_MIN_PRIV_BITS: u8 = 52;

// Get the surjection inputs in the elements core defined order
fn surjection_inputs<C: Signing>(
    pset: &Pset,
    secp: &Secp256k1<C>,
    utxo_sec: &[TxOutSecrets],
) -> Result<Vec<(Generator, Tag, Tweak)>, InitError> {
    let mut ret = vec![];
    for (i, inp) in pset.inputs().iter().enumerate() {
        let utxo = inp.witness_utxo.as_ref().ok_or(InitError::UtxoMissing(i))?;
        let in_gen = utxo.asset.into_asset_gen(secp);
        let in_gen = in_gen.ok_or(InitError::NullAsset(i))?;
        // Input fixed tags don't really matter. Give fixed values here.
        let in_utxo = utxo_sec.get(i).ok_or(InitError::UtxoSecretLenMismatch)?;
        let tag = in_utxo.asset.into_tag();
        let abf = in_utxo.asset_bf.into_inner();
        ret.push((in_gen, tag, abf));

        if !inp.asset_issuance().inflation_keys.is_null() || !inp.asset_issuance().amount.is_null()
        {
            let (asset_id, token_id) = issuance_ids(inp);

            let issue_amt = inp.issuance_value_amount.unwrap_or(0);
            let token_amt = inp.issuance_inflation_keys.unwrap_or(0);

            if issue_amt > 0 || inp.issuance_value_comm.is_some() {
                let gen = Generator::new_unblinded(secp, asset_id.into_tag());
                ret.push((gen, asset_id.into_tag(), ZERO_TWEAK));
            }
            if token_amt > 0 || inp.issuance_inflation_keys_comm.is_some() {
                let gen = Generator::new_unblinded(secp, token_id.into_tag());
                ret.push((gen, token_id.into_tag(), ZERO_TWEAK));
            }
        }
    }
    Ok(ret)
}

// Get the asset_id, token_id from pset input
fn issuance_ids(inp: &pset::Input) -> (AssetId, AssetId) {
    let issue_nonce = inp.issuance_blinding_nonce.unwrap_or(ZERO_TWEAK);
    let entropy = if issue_nonce == ZERO_TWEAK {
        // new issuance
        let prevout = OutPoint {
            txid: inp.previous_txid,
            vout: inp.previous_output_index,
        };
        let contract_hash =
            ContractHash::from_inner(inp.issuance_asset_entropy.unwrap_or_default());
        AssetId::generate_asset_entropy(prevout, contract_hash)
    } else {
        // re-issuance
        sha256::Midstate::from_inner(inp.issuance_asset_entropy.unwrap_or([0u8; 32]))
    };
    let asset_id = AssetId::from_entropy(entropy);
    let token_id =
        AssetId::reissuance_token_from_entropy(entropy, inp.issuance_value_comm.is_some());

    (asset_id, token_id)
}

/// Errors while creating RT Covenant for a pset
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InitError {
    /// Pset must have at least two inputs
    AtleastTwoInputs,
    /// Pset related error
    PsetError(pset::Error),
    /// Unblind error
    UnBlindError(usize),
    /// Issuance already present in pset input
    IssuancePresent(usize),
    /// Witness utxo not present at the given pset input
    UtxoMissing(usize),
    /// Incorrect re-issuance asset
    InvalidInpAsset(usize),
    /// Encountered Null asset
    NullAsset(usize),
    /// Secp related errors
    Secp(miniscript::elements::secp256k1_zkp::Error),
    /// Uxto Secrets len must match the pest input len
    UtxoSecretLenMismatch,
    /// Must have explicit asset for blinding
    BlindConfAsset(usize),
    /// Must have explicit value for blinding
    BlindConfValue(usize),
    /// Must have b
    BlindingKeyAbsent(usize),
}

impl Error for InitError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            InitError::AtleastTwoInputs
            | InitError::IssuancePresent(_)
            | InitError::UtxoMissing(_)
            | InitError::NullAsset(_)
            | InitError::InvalidInpAsset(_)
            | InitError::UnBlindError(_)
            | InitError::BlindConfAsset(_)
            | InitError::BlindConfValue(_)
            | InitError::BlindingKeyAbsent(_)
            | InitError::UtxoSecretLenMismatch => None,
            InitError::PsetError(e) => Some(e),
            InitError::Secp(e) => Some(e),
        }
    }
}

impl fmt::Display for InitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InitError::AtleastTwoInputs => write!(f, "Pset must contain atleast two inputs"),
            InitError::PsetError(_e) => write!(f, "pset error"),
            InitError::IssuancePresent(i) => {
                write!(f, "Issuance already present in pset at index {}", i)
            }
            InitError::UtxoMissing(i) => {
                write!(f, "Witness UTXO not present at input index {}", i)
            }
            InitError::InvalidInpAsset(i) => write!(
                f,
                "Expected asset with either a asset blinding factor of 1 or 2 at index {}",
                i
            ),
            InitError::Secp(_e) => write!(f, "Secp"),
            InitError::NullAsset(i) => write!(f, "Found null asset at index {}", i),
            InitError::UtxoSecretLenMismatch => {
                write!(f, "Utxo secrets must have the same length as input utxos")
            }
            InitError::UnBlindError(i) => write!(f, "Unblinding error at index {}", i),
            InitError::BlindConfAsset(i) => {
                write!(f, "Already blinded asset at output index {}", i)
            }
            InitError::BlindConfValue(i) => {
                write!(f, "Already blinded value at output index {}", i)
            }
            InitError::BlindingKeyAbsent(i) => {
                write!(f, "Blinding key missing at output index {}", i)
            }
        }
    }
}
