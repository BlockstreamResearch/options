//! Create Call-Put options on elements
//!
// Coding conventions
#![forbid(unsafe_code)]
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
// #![deny(dead_code)]
// #![deny(unused_imports)]
#![deny(missing_docs)]
#![deny(unused_must_use)]

extern crate elements_miniscript as miniscript;

pub mod contract;
pub mod cov_scripts;
use std::collections::BTreeMap;
use std::{error, fmt};

pub use contract::{BaseParams, OptionsContract};
use contract::{Consts, FundingParams};
use miniscript::elements::confidential::{
    self, Asset, AssetBlindingFactor, Value, ValueBlindingFactor,
};
use miniscript::elements::hashes::Hash;
pub use miniscript::elements::pset;
pub use miniscript::elements::pset::PartiallySignedTransaction as Pset;
use miniscript::elements::secp256k1_zkp::rand::{CryptoRng, RngCore};
use miniscript::elements::secp256k1_zkp::{self as secp256k1, All, Secp256k1};
use miniscript::elements::{OutPoint, TxOut, TxOutSecrets, TxOutWitness, UnblindError};

use crate::contract::draft_contract_hash;

/// Trait for adding options contract support for Pset
pub trait OptionsExt {
    /// Initialize the option contract by creating a pair of re-issuance tokens
    /// sent to the address bound by the RT covenant.
    /// Mutates the pset by adding re-issuance inputs/outputs and blinding it.
    ///
    /// Unfortunately, due a bug in elements wallet, this will produce incorrect signatures in
    /// walletprocesspsbt. Because of this bug, you need to sign with
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
    /// * `blinding_sks` : A map from input index to blinding secrets. There is no need to provide
    /// mapping for explicit txouts
    ///
    /// # Returns:
    ///
    /// - The [OptionsContract] data structure to be used creating/interacting with options contract.
    fn issue_rts<R: RngCore + CryptoRng>(
        &mut self,
        secp: &Secp256k1<secp256k1::All>,
        rng: &mut R,
        params: BaseParams,
        blinding_sks: &BTreeMap<usize, secp256k1::SecretKey>,
    ) -> Result<OptionsContract, Error>;

    /// Similar to [`OptionsExt::issue_rts`], but allows to specify
    /// blinding factors instead of secrets keys.
    ///
    /// # Arguments:
    ///
    /// * `params`: The [`BaseParams`] defining this options contract
    /// * `txout_secrets` : The map for [`TxOutSecrets`] for each input.
    /// You need not provide secrets for explicit txouts
    ///
    /// # Returns:
    ///
    /// - The [OptionsContract] data structure to be used creating/interacting with options contract.
    fn issue_rts_with_blinds<R: RngCore + CryptoRng>(
        &mut self,
        secp: &Secp256k1<secp256k1::All>,
        rng: &mut R,
        params: BaseParams,
        txout_secrets: &BTreeMap<usize, TxOutSecrets>,
    ) -> Result<OptionsContract, Error>;

    /// Fund the options covenant by locking collateral. Issues the ORT/CRT to the parameters
    /// provided by [`FundingParams`].
    ///
    /// You can obtain this pset by using the `walletcreatefundedpsbt` RPC by adding one output with collateral asset
    /// and amount as `contract_size * num_contracts` with any dummy address.
    ///
    /// This API would create the pset
    /// 1) `num_contracts` ORT tokens are issued to `ort_dest_addr`
    /// 2) `num_contracts` CRT tokens are issued to `crt_dest_addr`
    /// 3) `num_contracts * size_of_contract` collateral asset is locked in covenant
    /// 4) Adds the CRT/ORT RT inputs in the first and second input position
    ///
    /// Unfortunately, due a bug in elements wallet, this will produce incorrect signatures in
    /// walletprocesspsbt. Because of this bug, you need to sign with
    /// `signrawtransactionwithwallet` after extracting it using [`Pset::extract_tx`]
    ///
    /// # Precondition:
    ///
    /// - Balanced unblinded pset with following structure.
    ///     - The first output should be the locked collateral output with amount contract_size * num of contracts.
    ///     - You can set the script pubkey of the this outputs to a dummy value.
    /// This API would correctly update the script pubkey.
    ///     - All other outputs that need blinding should have the corresponding blinding key set. There must be atleast
    /// one confidential output.
    ///     - The pset should be balanced and must have sufficient fees in bitcoin asset.
    ///
    ///
    /// # Arguments:
    ///
    /// * `contract`: The [`OptionsContract`] defining this options contract
    /// * `blinding_sks` : A map from input index to blinding secrets. There is no need to provide
    /// mapping for explicit txouts
    /// * `funding_params`: The [`FundingParams`] for issuing these assets. You can specify the number of
    /// contracts and destination addresses for CRT/ORT tokens here.
    ///
    fn fund_contract<R: RngCore + CryptoRng>(
        &mut self,
        secp: &Secp256k1<secp256k1::All>,
        rng: &mut R,
        contract: OptionsContract,
        blinding_sks: &BTreeMap<usize, secp256k1::SecretKey>,
        funding_params: &FundingParams,
    ) -> Result<(), Error>;

    /// Similar to [`OptionsExt::fund_contract`], but allows to specify
    /// blinding factors instead of secrets keys.
    ///
    /// # Arguments:
    ///
    /// *`txout_secrets` : The [`TxOutSecrets`] for each input
    fn fund_contract_with_blinds<R: RngCore + CryptoRng>(
        &mut self,
        secp: &Secp256k1<secp256k1::All>,
        rng: &mut R,
        contract: OptionsContract,
        txout_secrets: &[TxOutSecrets],
        funding_params: &FundingParams,
    ) -> Result<(), Error>;
}

impl OptionsExt for Pset {
    fn issue_rts<R: RngCore + CryptoRng>(
        &mut self,
        secp: &Secp256k1<secp256k1::All>,
        rng: &mut R,
        params: BaseParams,
        blinding_sks: &BTreeMap<usize, secp256k1::SecretKey>,
    ) -> Result<OptionsContract, Error> {
        let txout_secrets = pset_txout_secrets(self, secp, blinding_sks)?;
        self.issue_rts_with_blinds(secp, rng, params, &txout_secrets)
    }

    fn issue_rts_with_blinds<R: RngCore + CryptoRng>(
        &mut self,
        secp: &Secp256k1<secp256k1::All>,
        rng: &mut R,
        params: BaseParams,
        txout_secrets: &BTreeMap<usize, TxOutSecrets>,
    ) -> Result<OptionsContract, Error> {
        // Check that there are atleast two inputs
        if self.inputs().len() < 2 {
            return Err(Error::AtleastTwoInputs);
        }

        if txout_secrets.len() != self.inputs().len() {
            return Err(Error::UtxoSecretLenMismatch);
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
            // Check that inputs don't already have an issuance
            if self.inputs()[i].has_issuance() {
                return Err(Error::IssuancePresent(i));
            }

            self.inputs_mut()[i].issuance_value_amount = None;
            self.inputs_mut()[i].issuance_inflation_keys = Some(1);
            self.inputs_mut()[i].issuance_asset_entropy = Some(draft_contract_hash().into_inner());
        }

        let mut offset_vbf = ValueBlindingFactor::zero();
        for (_i, asset_id) in arr {
            let surject_inp = self.surjection_inputs(txout_secrets).unwrap();
            // let domain = surjection_inputs(&self, secp, &txout_secrets)?;
            // let out_tag = asset_id.into_tag();
            let out_abf = AssetBlindingFactor::one();
            let exp_asset = Asset::Explicit(asset_id);
            let (conf_asset, prf) = exp_asset.blind(rng, secp, out_abf, &surject_inp).unwrap();
            // let prf = SurjectionProof::new(secp, rng, out_tag, out_abf.into_inner(), &domain);
            // let prf = prf.map_err(|e| Error::Secp(e))?;

            let txout = TxOut {
                asset: conf_asset,
                value: confidential::Value::Explicit(1),
                nonce: confidential::Nonce::Null,
                script_pubkey: dest_spk.clone(),
                witness: TxOutWitness {
                    surjection_proof: Some(Box::new(prf)),
                    rangeproof: None,
                },
            };
            // Add the offset vbf from this output
            offset_vbf += ValueBlindingFactor::one(); // 1(amt) * 1(abf) + 0(vbf)
            self.add_output(pset::Output::from_txout(txout));
        }
        offset_vbf = -offset_vbf; // negate because this sum_inp - sum_out
        self.global.scalars.push(offset_vbf.into_inner());
        self.blind_last(rng, secp, txout_secrets).unwrap();
        // custom_blind_tx(self, secp, rng, &txout_secrets)?;
        Ok(contract)
    }

    fn fund_contract<R: RngCore + CryptoRng>(
        &mut self,
        secp: &Secp256k1<secp256k1::All>,
        _rng: &mut R,
        _contract: OptionsContract,
        blinding_sks: &BTreeMap<usize, secp256k1::SecretKey>,
        _funding_params: &FundingParams,
    ) -> Result<(), Error> {
        let _txout_secrets = pset_txout_secrets(self, secp, blinding_sks)?;
        todo!()
    }

    fn fund_contract_with_blinds<R: RngCore + CryptoRng>(
        &mut self,
        secp: &Secp256k1<secp256k1::All>,
        _rng: &mut R,
        contract: OptionsContract,
        _txout_secrets: &[TxOutSecrets],
        funding_params: &FundingParams,
    ) -> Result<(), Error> {
        // Check the structure of the pset
        // Check that there are atleast two inputs
        if self.inputs().len() < 2 {
            return Err(Error::AtleastTwoInputs);
        }

        let coll_out = self.outputs().get(0).ok_or(Error::MissingPsetOutput(0))?;
        let total_coll = contract.params().contract_size * funding_params.num_contracts;
        if coll_out.asset != Some(contract.params().coll_asset) {
            return Err(Error::IncorrectCollAsset);
        }
        if coll_out.amount != Some(total_coll) {
            return Err(Error::IncorrectCollAmount);
        }

        let asset_rts = [contract.crt_rt(), contract.ort_rt()];

        let mut in_rt_abfs = vec![];
        let mut out_rt_abfs = vec![];
        for (i, (inp, asset)) in self.inputs().iter().take(2).zip(asset_rts).enumerate() {
            // Check that value is one and they are blinded by either abf `1` or `2`
            let utxo = inp.witness_utxo.as_ref().ok_or(Error::UtxoMissing(0))?;
            let abfs = [AssetBlindingFactor::one(), AssetBlindingFactor::two()];
            let inp_abf_pos = abfs
                .iter()
                .position(|abf| utxo.asset == Asset::new_confidential(secp, asset, *abf))
                .ok_or(Error::InvalidRtInput(i))?;
            in_rt_abfs.push(abfs[inp_abf_pos]);
            out_rt_abfs.push(abfs[1 - inp_abf_pos]); // This alternates between the abfs
        }

        todo!()
    }
}

/// Helper function to compute txout secrets by rewinding the rangeproofs
fn pset_txout_secrets(
    pset: &Pset,
    secp: &Secp256k1<All>,
    blinding_sks: &BTreeMap<usize, secp256k1::SecretKey>,
) -> Result<BTreeMap<usize, TxOutSecrets>, Error> {
    let mut txout_secrets = BTreeMap::new();
    let zero_abf = AssetBlindingFactor::zero();
    let zero_vbf = ValueBlindingFactor::zero();
    for (i, inp) in pset.inputs().iter().enumerate() {
        let utxo = inp.witness_utxo.as_ref().ok_or(Error::UtxoMissing(i))?;
        match (utxo.asset, utxo.value) {
            (Asset::Explicit(asset), Value::Explicit(amt)) => {
                txout_secrets.insert(i, TxOutSecrets::new(asset, zero_abf, amt, zero_vbf));
            }
            (_, Value::Confidential(_)) => {
                let prf = inp
                    .in_utxo_rangeproof
                    .as_ref()
                    .ok_or(Error::InUtxoRangeProofMissing(i))?;

                // This allocation be avoided with a separate function, but would require
                // computing the ecdh key and unblinding logic here. The code below is cleaner
                // but does some allocations to use the nice unblind API.
                let mut utxo_with_prf = utxo.clone();
                utxo_with_prf.witness.rangeproof = Some(prf.clone());
                let blind_sk = blinding_sks.get(&i).ok_or(Error::BlindingSkAbsent(i))?;
                let secrets = utxo_with_prf
                    .unblind(secp, *blind_sk)
                    .map_err(|e| Error::UnBlindError(e, i))?;
                txout_secrets.insert(i, secrets);
            }
            _ => return Err(Error::PartiallyBlindedUtxo(i)),
        }
    }
    Ok(txout_secrets)
}

/// Errors while creating RT Covenant for a pset
#[derive(Debug)]
pub enum Error {
    /// Pset must have at least two inputs
    AtleastTwoInputs,
    /// Pset related error
    PsetError(pset::Error),
    /// Unblind error
    UnBlindError(UnblindError, usize),
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
    /// Must have blinding key
    BlindingKeyAbsent(usize),
    /// Must have input utxo rangeproof for rewinding
    InUtxoRangeProofMissing(usize),
    /// Partially blinded utxo. If utxo has no rangeproof, but only a surjection proof
    /// it is impossible to recover the blinding factors
    PartiallyBlindedUtxo(usize),
    /// Blinding secret key at the input index is missing
    BlindingSkAbsent(usize),
    /// Invalid Re-issuance token
    InvalidRtInput(usize),
    /// Missing Pset output
    MissingPsetOutput(usize),
    /// Incorrect collateral amount
    IncorrectCollAmount,
    /// Incorrect collateral asset
    IncorrectCollAsset,
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Error::AtleastTwoInputs
            | Error::IssuancePresent(_)
            | Error::UtxoMissing(_)
            | Error::NullAsset(_)
            | Error::InvalidInpAsset(_)
            | Error::BlindConfAsset(_)
            | Error::BlindConfValue(_)
            | Error::BlindingKeyAbsent(_)
            | Error::InUtxoRangeProofMissing(_)
            | Error::PartiallyBlindedUtxo(_)
            | Error::BlindingSkAbsent(_)
            | Error::InvalidRtInput(_)
            | Error::MissingPsetOutput(_)
            | Error::IncorrectCollAmount
            | Error::IncorrectCollAsset
            | Error::UtxoSecretLenMismatch => None,
            Error::UnBlindError(e, _i) => Some(e),
            Error::PsetError(e) => Some(e),
            Error::Secp(e) => Some(e),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::AtleastTwoInputs => write!(f, "Pset must contain atleast two inputs"),
            Error::PsetError(_e) => write!(f, "pset error"),
            Error::IssuancePresent(i) => {
                write!(f, "Issuance already present in pset at index {}", i)
            }
            Error::UtxoMissing(i) => {
                write!(f, "Witness UTXO not present at input index {}", i)
            }
            Error::InvalidInpAsset(i) => write!(
                f,
                "Expected asset with either a asset blinding factor of 1 or 2 at index {}",
                i
            ),
            Error::Secp(_e) => write!(f, "Secp"),
            Error::NullAsset(i) => write!(f, "Found null asset at index {}", i),
            Error::UtxoSecretLenMismatch => {
                write!(f, "Utxo secrets must have the same length as input utxos")
            }
            Error::UnBlindError(_e, i) => write!(f, "Unblinding error at index {}", i),
            Error::BlindConfAsset(i) => {
                write!(f, "Already blinded asset at output index {}", i)
            }
            Error::BlindConfValue(i) => {
                write!(f, "Already blinded value at output index {}", i)
            }
            Error::BlindingKeyAbsent(i) => {
                write!(f, "Blinding key missing at output index {}", i)
            }
            Error::InUtxoRangeProofMissing(i) => {
                write!(f, "Input uxto rangeproof missing {}", i)
            }
            Error::PartiallyBlindedUtxo(i) => {
                write!(f, "Input utxo at index {} cannot be rewinded.", i)
            }
            Error::BlindingSkAbsent(i) => write!(f, "Blinding sk missing at input index {}", i),
            Error::InvalidRtInput(i) => write!(
                f,
                "Invalid Re-issunace token blinding factor for input {}",
                i
            ),
            Error::MissingPsetOutput(i) => write!(f, "Missing pset output at index {}", i),
            Error::IncorrectCollAmount => write!(
                f,
                "Collateral amount does not match contract_size * num_contracts"
            ),
            Error::IncorrectCollAsset => {
                write!(f, "Collateral asset does not match the asset in covenant")
            }
        }
    }
}

// // The in-built blinding APIs are not help because
// // 1) elementds always blinds pset issuances. There is no way to set
// // that we don't need blinding for issunaces
// // 2) Doing partial blinding without considering issuances makes it harder
// // to balance out the surjection/rangeproofs.
// fn custom_blind_tx<R: RngCore + CryptoRng>(
//     pset: &mut Pset,
//     secp: &Secp256k1<All>,
//     rng: &mut R,
//     utxo_sec: &[TxOutSecrets],
// ) -> Result<(), Error> {
//     let surjection_inputs = surjection_inputs(pset, &secp, utxo_sec)?;
//     let mut inp_v_secrets = vec![];
//     for (i, inp) in pset.inputs().iter().enumerate() {
//         inp_v_secrets.push((
//             utxo_sec[i].value,
//             utxo_sec[i].asset_bf,
//             utxo_sec[i].value_bf,
//         ));

//         if inp.has_issuance() {
//             inp_v_secrets.push((1, AssetBlindingFactor::zero(), ValueBlindingFactor::zero()));
//         }
//     }

//     // blind the last txout
//     let out = &pset.outputs()[0];
//     let asset = out.asset.ok_or(Error::BlindConfAsset(0))?;
//     let value = out.amount.ok_or(Error::BlindConfValue(0))?;
//     let out_abf = AssetBlindingFactor::new(rng);
//     let out_asset = confidential::Asset::new_confidential(&secp, asset, out_abf);
//     let out_asset_commitment = out_asset.commitment().expect("confidential asset");

//     // Balance the equation for the last blinding factor
//     let mut exp_out_secrets = vec![];
//     for (i, out) in pset.outputs().iter().enumerate() {
//         if out.blinding_key.is_none() {
//             let amt = out.amount.ok_or(Error::BlindConfValue(i))?;
//             // Outputs two and three are crt/ort rt outputs. Initially they use one asset blinding factor
//             let abf = if i == 2 || i == 3 {
//                 AssetBlindingFactor::one()
//             } else {
//                 AssetBlindingFactor::zero()
//             };
//             exp_out_secrets.push((amt, abf, ValueBlindingFactor::zero()));
//         }
//     }
//     let final_vbf =
//         ValueBlindingFactor::last(&secp, value, out_abf, &inp_v_secrets, &exp_out_secrets);

//     let value_commitment =
//         confidential::Value::new_confidential(&secp, value, out_asset_commitment, final_vbf);

//     let value_commitment = value_commitment.commitment().expect("confidential value");

//     let receiver_blinding_pk = &pset.outputs()[0]
//         .blinding_key
//         .ok_or(Error::BlindingKeyAbsent(0))?;
//     let (nonce, shared_secret) =
//         confidential::Nonce::new_confidential(rng, &secp, &receiver_blinding_pk.inner);

//     let message = RangeProofMessage { asset, bf: out_abf };
//     let rangeproof = RangeProof::new(
//         &secp,
//         RANGEPROOF_MIN_VALUE,
//         value_commitment,
//         value,
//         final_vbf.into_inner(),
//         &message.to_bytes(),
//         pset.outputs()[0].script_pubkey.as_bytes().as_ref(),
//         shared_secret,
//         RANGEPROOF_EXP_SHIFT,
//         RANGEPROOF_MIN_PRIV_BITS,
//         out_asset_commitment,
//     )
//     .map_err(Error::Secp)?;

//     let surjection_proof = SurjectionProof::new(
//         &secp,
//         rng,
//         asset.into_tag(),
//         out_abf.into_inner(),
//         surjection_inputs.as_ref(),
//     )
//     .map_err(Error::Secp)?;

//     // mutate the pset
//     {
//         pset.outputs_mut()[0].value_rangeproof = Some(Box::new(rangeproof));
//         pset.outputs_mut()[0].asset_surjection_proof = Some(Box::new(surjection_proof));
//         pset.outputs_mut()[0].amount_comm = Some(value_commitment);
//         pset.outputs_mut()[0].asset_comm = Some(out_asset_commitment);
//         pset.outputs_mut()[0].amount = None; // Reset to none so that we don't have to provide blinding proof
//         pset.outputs_mut()[0].asset = None; // Reset to none so that we don't have to provide blinding proof
//         pset.outputs_mut()[0].ecdh_pubkey = nonce.commitment().map(|pk| bitcoin::PublicKey {
//             inner: pk,
//             compressed: true,
//         });
//     }
//     Ok(())
// }

// pub(crate) struct RangeProofMessage {
//     pub(crate) asset: AssetId,
//     pub(crate) bf: AssetBlindingFactor,
// }

// impl RangeProofMessage {
//     pub(crate) fn to_bytes(&self) -> [u8; 64] {
//         let mut message = [0u8; 64];

//         message[..32].copy_from_slice(self.asset.into_tag().as_ref());
//         message[32..].copy_from_slice(self.bf.into_inner().as_ref());

//         message
//     }
// }

// pub(crate) const RANGEPROOF_MIN_VALUE: u64 = 1;
// pub(crate) const RANGEPROOF_EXP_SHIFT: i32 = 0;
// pub(crate) const RANGEPROOF_MIN_PRIV_BITS: u8 = 52;

// // Get the surjection inputs in the elements core defined order
// fn surjection_inputs<C: Signing>(
//     pset: &Pset,
//     secp: &Secp256k1<C>,
//     utxo_sec: &[TxOutSecrets],
// ) -> Result<Vec<(Generator, Tag, Tweak)>, Error> {
//     let mut ret = vec![];
//     for (i, inp) in pset.inputs().iter().enumerate() {
//         let utxo = inp.witness_utxo.as_ref().ok_or(Error::UtxoMissing(i))?;
//         let in_gen = utxo.asset.into_asset_gen(secp);
//         let in_gen = in_gen.ok_or(Error::NullAsset(i))?;
//         // Input fixed tags don't really matter. Give fixed values here.
//         let in_utxo = utxo_sec.get(i).ok_or(Error::UtxoSecretLenMismatch)?;
//         let tag = in_utxo.asset.into_tag();
//         let abf = in_utxo.asset_bf.into_inner();
//         ret.push((in_gen, tag, abf));

//         if !inp.asset_issuance().inflation_keys.is_null() || !inp.asset_issuance().amount.is_null()
//         {
//             let (asset_id, token_id) = issuance_ids(inp);

//             let issue_amt = inp.issuance_value_amount.unwrap_or(0);
//             let token_amt = inp.issuance_inflation_keys.unwrap_or(0);

//             if issue_amt > 0 || inp.issuance_value_comm.is_some() {
//                 let gen = Generator::new_unblinded(secp, asset_id.into_tag());
//                 ret.push((gen, asset_id.into_tag(), ZERO_TWEAK));
//             }
//             if token_amt > 0 || inp.issuance_inflation_keys_comm.is_some() {
//                 let gen = Generator::new_unblinded(secp, token_id.into_tag());
//                 ret.push((gen, token_id.into_tag(), ZERO_TWEAK));
//             }
//         }
//     }
//     Ok(ret)
// }

// // Get the asset_id, token_id from pset input
// fn issuance_ids(inp: &pset::Input) -> (AssetId, AssetId) {
//     let issue_nonce = inp.issuance_blinding_nonce.unwrap_or(ZERO_TWEAK);
//     let entropy = if issue_nonce == ZERO_TWEAK {
//         // new issuance
//         let prevout = OutPoint {
//             txid: inp.previous_txid,
//             vout: inp.previous_output_index,
//         };
//         let contract_hash =
//             ContractHash::from_inner(inp.issuance_asset_entropy.unwrap_or_default());
//         AssetId::generate_asset_entropy(prevout, contract_hash)
//     } else {
//         // re-issuance
//         sha256::Midstate::from_inner(inp.issuance_asset_entropy.unwrap_or([0u8; 32]))
//     };
//     let asset_id = AssetId::from_entropy(entropy);
//     let token_id =
//         AssetId::reissuance_token_from_entropy(entropy, inp.issuance_value_comm.is_some());

//     (asset_id, token_id)
// }
