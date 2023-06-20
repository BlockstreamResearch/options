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

#[cfg(feature = "serde")]
pub use actual_serde as serde;
use elements::locktime;

pub extern crate elements_miniscript as miniscript;

pub mod contract;
pub mod cov_scripts;
use std::collections::HashMap;
use std::{error, fmt};

use contract::{abf_to_vbf, Consts, CovUserParams, FundingParams};
pub use contract::{BaseParams, OptionsContract};
use cov_scripts::{op_return, TrDesc};
use miniscript::bitcoin::PublicKey;
use miniscript::elements::confidential::{
    self, Asset, AssetBlindingFactor, Value, ValueBlindingFactor,
};
use miniscript::elements::hashes::Hash;
pub use miniscript::elements::pset;
pub use miniscript::elements::pset::PartiallySignedTransaction as Pset;
use miniscript::elements::secp256k1_zkp::rand::{CryptoRng, RngCore};
use miniscript::elements::secp256k1_zkp::{self as secp256k1, All, Secp256k1};
use miniscript::elements::{
    AssetId, BlindError, BlockHash, OutPoint, Script, TxOut, TxOutSecrets, TxOutWitness,
    UnblindError,
};
use miniscript::psbt::{PsbtExt, UtxoUpdateError};
use pset::PsetBlindError;

use crate::cov_scripts::translate_xpk_desc_pubkey;

/// Trait for adding options contract support for Pset
pub trait OptionsExt {
    /// Initialize the option contract by creating a pair of re-issuance tokens
    /// sent to the address bound by the RT covenant.
    /// Mutates the pset by adding re-issuance inputs/outputs and blinding it.
    /// When possible, [`OptionsExt::issue_rts`] should be used instead.
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
    fn issue_rts_with_blinding_keys<R: RngCore + CryptoRng>(
        &mut self,
        secp: &Secp256k1<secp256k1::All>,
        rng: &mut R,
        params: BaseParams,
        blinding_sks: &HashMap<usize, secp256k1::SecretKey>,
    ) -> Result<OptionsContract, Error>;

    /// Issues RT tokens without blinds inputs. This can be used with elements wallet that does not blind
    /// issuances by default. This is supported since elements 22.0.
    ///
    /// This outputs a pset that can be directly used with walletprocesspsbt to blind and sign.
    /// # Precondition:
    ///
    /// - Unblinded balanced pset with atleast two(possibly confidential) bitcoin inputs and two outputs.
    /// - The fees should account for the one tx rangeproof, and two issued outputs with surjection proofs.
    ///
    /// # Arguments:
    ///
    /// * `params`: The [`BaseParams`] defining this options contract
    ///
    /// # Returns:
    ///
    /// - The [OptionsContract] data structure to be used creating/interacting with options contract.
    fn issue_rts<R: RngCore + CryptoRng>(
        &mut self,
        secp: &Secp256k1<secp256k1::All>,
        rng: &mut R,
        params: BaseParams,
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
        txout_secrets: &HashMap<usize, TxOutSecrets>,
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
    /// 4) Adds the CRT/ORT RT inputs in the first and second input and output positions
    ///
    /// Unfortunately, due a bug in elements wallet, this will produce incorrect signatures in
    /// walletprocesspsbt. Because of this bug, you need to sign with
    /// `signrawtransactionwithwallet` after extracting it using [`Pset::extract_tx`]
    ///
    /// # Precondition:
    ///
    /// - Balanced unblinded pset with following structure.
    ///     - The first output should be the locked collateral output with amount contract_size * num of contracts.
    ///     - You can set the script pubkey of the this output to a dummy value.
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
    /// mapping for explicit txouts. Because the transaction structure changes after adding re-issuance
    /// inputs, this map is updated with rt token secrets.
    /// * `funding_params`: The [`FundingParams`] for issuing these assets. You can specify the number of
    /// contracts and destination addresses for CRT/ORT tokens here.
    ///
    fn fund_contract_with_blinding_keys<R: RngCore + CryptoRng>(
        &mut self,
        secp: &Secp256k1<secp256k1::All>,
        rng: &mut R,
        contract: OptionsContract,
        blinding_sks: &HashMap<usize, secp256k1::SecretKey>,
        funding_params: &FundingParams,
    ) -> Result<(), Error>;

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
    /// 4) Adds the CRT/ORT RT inputs in the first and second input and output positions
    ///
    /// This outputs a pset that can be directly used with walletprocesspsbt to blind and sign.
    ///
    /// # Precondition:
    ///
    /// - Balanced unblinded pset with following structure.
    ///     - The first output should be the locked collateral output with amount contract_size * num of contracts.
    ///     - You can set the script pubkey of the this output to a dummy value.
    /// This API would correctly update the script pubkey.
    ///     - All other outputs that need blinding should have the corresponding blinding key set. There must be atleast
    /// one confidential output.
    ///     - The pset should be balanced and must have sufficient fees in bitcoin asset.
    ///
    /// # Arguments:
    ///
    /// * `contract`: The [`OptionsContract`] defining this options contract
    /// * `funding_params`: The [`FundingParams`] for issuing these assets. You can specify the number of
    /// contracts and destination addresses for CRT/ORT tokens here.
    ///
    fn fund_contract<R: RngCore + CryptoRng>(
        &mut self,
        secp: &Secp256k1<secp256k1::All>,
        rng: &mut R,
        contract: OptionsContract,
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
        txout_secrets: &mut HashMap<usize, TxOutSecrets>,
        funding_params: &FundingParams,
    ) -> Result<(), Error>;

    /// Exercise the options covenant by spending settlement asset and retrieving locking collateral.
    /// The parameters to exercise can be provided by the [`CovUserParams`]
    ///
    /// You can obtain this pset by using the `walletcreatefundedpsbt` RPC by adding
    /// 1) Output at index 0 with ort asset with `num_contracts` amount sent to any dummy address.
    /// 2) Output at index 1 with settlement asset and amount as `strike_price * num_contracts` with any dummy address.
    ///
    /// This API would modify the pset as follows:
    /// 1) `num_contracts` ORT tokens are burned to an OP_RETURN
    /// 2) `num_contracts * stike_price` settlement asset sent to `settlement_covenant`
    /// 3) Adds the collateral input at input position 0
    /// 4) Optional collateral change output if necessary
    /// 5) `num_contracts * contract_size` collateral send to `dest_addr`
    ///
    /// The modified pset from the function can then be pass `walletprocesspsbt` to blind and sign.
    /// The output can later be finalized using `finalizepsbt` and broadcasted.
    ///
    /// # Precondition:
    ///
    /// - Balanced unblinded pset with following structure.
    ///     - Output at index 0 should be `ort_asset` with amount `num_contracts`.
    ///     - Output at index 1 should be `settlement_asset` with amount `num_contracts * strike_price`.
    ///     - You can set the script pubkey of the these outputs to a dummy value.
    /// This API would correctly update these script pubkeys.
    ///     - The pset should be balanced and must have sufficient fees in bitcoin asset.
    ///
    /// # Arguments:
    ///
    /// * `contract`: The [`OptionsContract`] defining this options contract
    /// * `user_params`: The [`CovUserParams`] for exercising this contract. You can specify the number of
    /// contracts to exercise and destination addresses for collateral here.
    ///
    fn exercise_contract(
        &mut self,
        secp: &Secp256k1<secp256k1::All>,
        contract: OptionsContract,
        user_params: &CovUserParams,
    ) -> Result<(), Error>;

    /// Cancel the options covenant by burning both the CRT and ORT tokens. This unlocks
    /// locked asset from the covenant and sends to the specified address.
    /// The parameters to cancel can be provided by the [`CancelParams`]
    ///
    /// You can obtain this pset by using the `walletcreatefundedpsbt` RPC by adding
    /// 1) Output at index 0 with crt asset with `num_contracts` amount sent to any dummy address.
    /// 2) Output at index 1 with ort asset with `num_contracts` amount sent to any dummy address.
    ///
    /// This API would modify the pset as follows:
    /// 1) `num_contracts` CRT tokens are burned to an OP_RETURN
    /// 2) `num_contracts` ORT tokens are burned to an OP_RETURN
    /// 3) Adds the collateral input at input position 0
    /// 4) Optional collateral change output if necessary
    /// 5) `num_contracts * contract_size` collateral send to `dest_addr`
    ///
    /// The modified pset from the function can then be pass `walletprocesspsbt` to blind and sign.
    /// The output can later be finalized using `finalizepsbt` and broadcasted.
    ///
    /// # Precondition:
    ///
    /// - Balanced unblinded pset with following structure.
    ///     - Output at index 0 should be `crt_asset` with amount `num_contracts`.
    ///     - Output at index 1 should be `ort_asset` with amount `num_contracts`.
    ///     - You can set the script pubkey of the these outputs to a dummy value.
    /// This API would correctly update these script pubkeys.
    ///     - The pset should be balanced and must have sufficient fees in bitcoin asset.
    ///
    /// # Arguments:
    ///
    /// * `contract`: The [`OptionsContract`] defining this options contract
    /// * `user_params`: The [`CovUserParams`] for cancelling this contract. You can specify the number of
    /// contracts to cancel and destination addresses for collateral here.
    ///
    fn cancel_contract(
        &mut self,
        secp: &Secp256k1<secp256k1::All>,
        contract: OptionsContract,
        user_params: &CovUserParams,
    ) -> Result<(), Error>;

    /// Claim the locked collateral the options covenant that has expired by buring CRT tokens.
    /// This unlocks locked asset from the covenant and sends to the specified address.
    /// The parameters to cancel can be provided by the [`CancelParams`]
    ///
    /// You can obtain this pset by using the `walletcreatefundedpsbt` RPC by adding
    /// 1) Output at index 0 with crt asset with `num_contracts` amount sent to any dummy address.
    ///
    /// This API would modify the pset as follows:
    /// 1) `num_contracts` CRT tokens are burned to an OP_RETURN
    /// 2) Adds the collateral input at input position 0
    /// 3) Optional collateral change output if necessary
    /// 4) `num_contracts * contract_size` collateral send to `dest_addr`
    ///
    /// The modified pset from the function can then be pass `walletprocesspsbt` to blind and sign.
    /// The output can later be finalized using `finalizepsbt` and broadcasted.
    ///
    /// # Precondition:
    ///
    /// - Balanced unblinded pset with following structure.
    ///     - Output at index 0 should be `crt_asset` with amount `num_contracts`.
    ///     - You can set the script pubkey of the these outputs to a dummy value.
    /// This API would correctly update these script pubkeys.
    ///     - The pset should be balanced and must have sufficient fees in bitcoin asset.
    ///
    /// # Arguments:
    ///
    /// * `contract`: The [`OptionsContract`] defining this options contract
    /// * `user_params`: The [`CovUserParams`] for expiry this contract. You can specify the number of
    /// contracts to expire and destination addresses for collateral here.
    ///
    fn expiry_contract(
        &mut self,
        secp: &Secp256k1<secp256k1::All>,
        contract: OptionsContract,
        user_params: &CovUserParams,
    ) -> Result<(), Error>;

    /// Claim the settlement asset from settlement covenant by burning CRT tokens.
    ///
    /// You can obtain this pset by using the `walletcreatefundedpsbt` RPC by adding
    /// 1) Output at index 0 with crt asset with `num_contracts` amount sent to any dummy address.
    ///
    /// This API would modify the pset as follows:
    /// 1) `num_contracts` CRT tokens are burned to an OP_RETURN
    /// 2) Adds the settlement input at input position 0
    /// 3) Optional settlement change output if necessary
    /// 4) `num_contracts * strike_price` settlement send to `settlement_dest_addr`
    ///
    /// The modified pset from the function can then be pass `walletprocesspsbt` to blind and sign.
    /// The output can later be finalized using `finalizepsbt` and broadcasted.
    ///
    /// # Precondition:
    ///
    /// - Balanced unblinded pset with following structure.
    ///     - Output at index 0 should be `crt_asset` with amount `num_contracts`.
    ///     - You can set the script pubkey of the these outputs to a dummy value.
    /// This API would correctly update these script pubkeys.
    ///     - The pset should be balanced and must have sufficient fees in bitcoin asset.
    ///
    /// # Arguments:
    ///
    /// * `contract`: The [`OptionsContract`] defining this options contract
    /// * `user_params`: The [`CovUserParams`] for expiry this contract. You can specify the number of
    /// contracts to expire and destination addresses for collateral here.
    ///
    fn settle_contract(
        &mut self,
        secp: &Secp256k1<secp256k1::All>,
        contract: OptionsContract,
        user_params: &CovUserParams,
    ) -> Result<(), Error>;
}

impl OptionsExt for Pset {
    fn issue_rts_with_blinding_keys<R: RngCore + CryptoRng>(
        &mut self,
        secp: &Secp256k1<secp256k1::All>,
        rng: &mut R,
        params: BaseParams,
        blinding_sks: &HashMap<usize, secp256k1::SecretKey>,
    ) -> Result<OptionsContract, Error> {
        let txout_secrets = pset_txout_secrets(self, secp, blinding_sks)?;
        self.issue_rts_with_blinds(secp, rng, params, &txout_secrets)
    }

    fn issue_rts<R: RngCore + CryptoRng>(
        &mut self,
        secp: &Secp256k1<secp256k1::All>,
        rng: &mut R,
        params: BaseParams,
    ) -> Result<OptionsContract, Error> {
        // Check that there are atleast two inputs
        if self.inputs().len() < 2 {
            return Err(Error::AtleastTwoInputs);
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
        let contract = OptionsContract::new(params, crt_prevout, ort_prevout);

        let fund_desc = contract.funding_desc(secp);
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
            self.inputs_mut()[i].issuance_asset_entropy =
                Some(contract.params().contract_hash.into_inner());
        }

        let mut offset_vbf = ValueBlindingFactor::zero();
        let surject_inp = self.surjection_inputs(&HashMap::new())?;
        for (_i, asset_id) in arr {
            let out_abf = AssetBlindingFactor::one();
            let exp_asset = Asset::Explicit(asset_id);
            let (conf_asset, prf) = exp_asset
                .blind(rng, secp, out_abf, &surject_inp)
                .map_err(BlindError::ConfidentialTxOutError)?;

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
        self.global.scalars.push(offset_vbf.into_inner());
        Ok(contract)
    }

    fn issue_rts_with_blinds<R: RngCore + CryptoRng>(
        &mut self,
        secp: &Secp256k1<secp256k1::All>,
        rng: &mut R,
        params: BaseParams,
        txout_secrets: &HashMap<usize, TxOutSecrets>,
    ) -> Result<OptionsContract, Error> {
        if txout_secrets.len() != self.inputs().len() {
            return Err(Error::UtxoSecretLenMismatch);
        }

        let contract = self.issue_rts(secp, rng, params)?;
        self.blind_last(rng, secp, txout_secrets)?;
        Ok(contract)
    }

    fn fund_contract<R: RngCore + CryptoRng>(
        &mut self,
        secp: &Secp256k1<secp256k1::All>,
        rng: &mut R,
        contract: OptionsContract,
        funding_params: &FundingParams,
    ) -> Result<(), Error> {
        let coll_out = self.outputs().get(0).ok_or(Error::MissingPsetOutput(0))?;
        let total_coll = contract.params().contract_size * funding_params.num_contracts;
        if coll_out.asset != Some(contract.params().coll_asset) {
            return Err(Error::IncorrectCovAsset {
                exp_asset: contract.params().coll_asset,
                got_asset: coll_out.asset.ok_or(Error::MissingOutputAssetId(0))?,
                name: "Collateral",
                pos: 0,
            });
        }
        if coll_out.amount != Some(total_coll) {
            return Err(Error::IncorrectCovAmount {
                exp_amount: total_coll,
                got_amount: coll_out.amount.ok_or(Error::MissingOutputAmount(0))?,
                name: "Collateral",
                pos: 0,
            });
        }

        // Set the script pubkey correctly
        self.outputs_mut()[0].script_pubkey = contract.coll_desc().script_pubkey();

        #[rustfmt::skip]
        let arr = [
            (&funding_params.crt_prevout, contract.crt_rt(), contract.crt(), contract.crt_reissue_entropy(), &funding_params.crt_dest_addr),
            (&funding_params.ort_prevout, contract.ort_rt(), contract.ort(), contract.ort_reissue_entropy(), &funding_params.ort_dest_addr),
        ];
        let zero_vbf = ValueBlindingFactor::zero();
        let abfs = [AssetBlindingFactor::one(), AssetBlindingFactor::two()];
        let mut out_rt_abfs = vec![];
        let mut offset_vbf = zero_vbf;
        // Mutate the pset by adding:
        // 1) Re-issuance inputs along with issuance information to pset inputs.
        // 2) Re-issuance outputs to pset outputs.
        // 3) Issuance outputs to pset outputs.
        let mut txout_secrets = HashMap::new();
        for (i, ((prevout, utxo), token, asset, entropy, addr)) in arr.iter().enumerate() {
            let mut inp = pset::Input::default();

            // 1) Mutate input. Fill in re-issuance information
            inp.previous_txid = prevout.txid;
            inp.previous_output_index = prevout.vout;
            inp.witness_utxo = Some(utxo.clone());
            inp.issuance_value_amount = Some(funding_params.num_contracts);
            let inp_abf_pos = abfs
                .iter()
                .position(|abf| utxo.asset == Asset::new_confidential(secp, *token, *abf))
                .ok_or(Error::InvalidRtInput(i))?;
            inp.issuance_blinding_nonce = Some(abfs[inp_abf_pos].into_inner());
            inp.issuance_asset_entropy = Some(entropy.into_inner());
            self.add_input(inp);
            let last_pos = self.inputs().len() - 1;
            self.inputs_mut().swap(i, last_pos); // Swap to the correct position
            for o in self.outputs_mut().iter_mut() {
                if o.blinder_index == Some(i as u32) {
                    o.blinder_index = Some(last_pos as u32)
                }
            }

            // Swap the secrets
            let secrets = TxOutSecrets::new(*token, abfs[inp_abf_pos], 1, zero_vbf);
            txout_secrets.insert(i, secrets); // ReIssuance at position i

            // Compute the vbf offset when this input is added
            offset_vbf += abf_to_vbf(abfs[inp_abf_pos]); // abf * amt(=1) + vbf(=0) = abf

            // Add reissuance outputs
            let mut out = pset::Output::default();
            out.amount = Some(1);
            out.script_pubkey = utxo.script_pubkey.clone();
            out.asset = Some(*token);
            out_rt_abfs.push(abfs[1 - inp_abf_pos]); // This does the switching between abfs
            self.insert_output(out, i);

            // Add issuances to the target address
            let mut out = pset::Output::default();
            out.asset = Some(*asset);
            out.amount = Some(funding_params.num_contracts);
            out.script_pubkey = addr.script_pubkey();
            // out.blinding_key = addr.blinding_pubkey.map(PublicKey::new);
            self.add_output(out);
        }

        // Since all the inputs issuances and re-issuances are added, we can now create surjection proofs
        // for blinding re-issuances
        let surject_inp = self.surjection_inputs(&txout_secrets)?;
        for (i, out) in self.outputs_mut().iter_mut().enumerate().take(2) {
            let asset = Asset::Explicit(out.asset.expect("Output token already filled in"));
            let (conf_asset, prf) = asset
                .blind(rng, secp, out_rt_abfs[i], &surject_inp)
                .map_err(BlindError::ConfidentialTxOutError)?;
            out.asset_comm = conf_asset.commitment();
            out.asset_surjection_proof = Some(Box::new(prf));

            offset_vbf += -abf_to_vbf(out_rt_abfs[i]) // abf*amt(1) + vbf(=0) = abf
        }

        offset_vbf = -offset_vbf; // Negate the offset vbf
                                  // Blind the remaining txouts
        self.global.scalars.push(offset_vbf.into_inner());

        // Compute the two witnesses for covenant scripts
        let fund_desc = contract.funding_desc(secp);
        let fund_desc = translate_xpk_desc_pubkey(fund_desc);
        for i in 0..2 {
            self.update_input_with_descriptor(i, &fund_desc)
                .map_err(|e| Error::UtxoUpdate(i, e))?;
            // There are no signatures here, so we can use default blockhash
            // If we add sigs to covenant, we would also need to pass the genesis hash here
            self.finalize_inp_mall_mut(secp, i, BlockHash::all_zeros())
                .map_err(|e| Error::Finalize(i, e))?;
        }
        Ok(())
    }

    fn fund_contract_with_blinding_keys<R: RngCore + CryptoRng>(
        &mut self,
        secp: &Secp256k1<secp256k1::All>,
        rng: &mut R,
        contract: OptionsContract,
        blinding_sks: &HashMap<usize, secp256k1::SecretKey>,
        funding_params: &FundingParams,
    ) -> Result<(), Error> {
        let mut txout_secrets = pset_txout_secrets(self, secp, blinding_sks)?;
        self.fund_contract_with_blinds(secp, rng, contract, &mut txout_secrets, funding_params)
    }

    fn fund_contract_with_blinds<R: RngCore + CryptoRng>(
        &mut self,
        secp: &Secp256k1<secp256k1::All>,
        rng: &mut R,
        contract: OptionsContract,
        txout_secrets: &mut HashMap<usize, TxOutSecrets>,
        funding_params: &FundingParams,
    ) -> Result<(), Error> {
        self.fund_contract(secp, rng, contract, funding_params)?;
        let last_inp = self.inputs().len() - 1;
        for i in 0..2 {
            let v = txout_secrets.get(&i).copied();
            match v {
                Some(secrets) => {
                    txout_secrets.insert(last_inp - 2 + i, secrets);
                }
                None => {}
            }
        }
        self.blind_last(rng, secp, txout_secrets)?;
        Ok(())
    }

    fn exercise_contract(
        &mut self,
        secp: &Secp256k1<secp256k1::All>,
        contract: OptionsContract,
        user_params: &CovUserParams,
    ) -> Result<(), Error> {
        // Check the pre-conditions
        let ort_burn_out = self.outputs().get(0).ok_or(Error::MissingPsetOutput(0))?;
        if ort_burn_out.asset != Some(contract.ort()) {
            return Err(Error::IncorrectCovAsset {
                exp_asset: contract.ort(),
                got_asset: ort_burn_out.asset.ok_or(Error::MissingOutputAssetId(0))?,
                name: "Exercise: ORT output",
                pos: 0,
            });
        }
        if ort_burn_out.amount != Some(user_params.num_contracts) {
            return Err(Error::IncorrectCovAmount {
                exp_amount: user_params.num_contracts,
                got_amount: ort_burn_out.amount.ok_or(Error::MissingOutputAmount(0))?,
                name: "Exercise: ORT output",
                pos: 0,
            });
        }
        let settle_out = self.outputs().get(1).ok_or(Error::MissingPsetOutput(1))?;
        if settle_out.asset != Some(contract.params().settle_asset) {
            return Err(Error::IncorrectCovAsset {
                exp_asset: contract.params().settle_asset,
                got_asset: settle_out.asset.ok_or(Error::MissingOutputAssetId(1))?,
                name: "Exercise: Settlement output",
                pos: 1,
            });
        }
        let settle_amt = user_params.num_contracts * contract.params().strike_price;
        if settle_out.amount != Some(settle_amt) {
            return Err(Error::IncorrectCovAmount {
                exp_amount: settle_amt,
                got_amount: settle_out.amount.ok_or(Error::MissingOutputAmount(1))?,
                name: "Exercise: Settlement output",
                pos: 1,
            });
        }
        let desc = contract.coll_desc();
        let cov_ty = UserCovType::Collateral;
        cov_input_checks(user_params, &contract, &desc, cov_ty)?;

        // Pre-conditions checked
        //-----------------------------------------------
        self.outputs_mut()[0].script_pubkey = op_return();
        self.outputs_mut()[1].script_pubkey = contract.settle_desc().script_pubkey();
        for i in 0..2 {
            // make sure we don't blind the covenant outputs by removing blinding details
            self.outputs_mut()[i].blinding_key = None;
            self.outputs_mut()[i].blinder_index = None;
        }
        let locktime = Some(contract.params().start);
        pset_add_cov(self, secp, &user_params, &contract, desc, locktime, cov_ty)?;
        Ok(())
    }

    fn cancel_contract(
        &mut self,
        secp: &Secp256k1<secp256k1::All>,
        contract: OptionsContract,
        user_params: &CovUserParams,
    ) -> Result<(), Error> {
        // Check the pre-conditions
        let crt_burn_out = self.outputs().get(0).ok_or(Error::MissingPsetOutput(0))?;
        let ort_burn_out = self.outputs().get(1).ok_or(Error::MissingPsetOutput(1))?;
        let arr = [
            (crt_burn_out, contract.crt(), "Cancel: CRT output"),
            (ort_burn_out, contract.ort(), "Cancel: ORT output"),
        ];

        for (i, (out, asset, name_str)) in arr.iter().enumerate() {
            if out.asset != Some(*asset) {
                return Err(Error::IncorrectCovAsset {
                    exp_asset: *asset,
                    got_asset: out.asset.ok_or(Error::MissingOutputAssetId(i))?,
                    name: name_str,
                    pos: i,
                });
            }
            if out.amount != Some(user_params.num_contracts) {
                return Err(Error::IncorrectCovAmount {
                    exp_amount: user_params.num_contracts,
                    got_amount: out.amount.ok_or(Error::MissingOutputAmount(i))?,
                    name: name_str,
                    pos: i,
                });
            }
        }

        let coll_desc = contract.coll_desc();
        let cov_ty = UserCovType::Collateral;
        cov_input_checks(user_params, &contract, &coll_desc, cov_ty)?;

        // Preconditions checked
        // ---------------------------------------
        self.outputs_mut()[0].script_pubkey = op_return();
        self.outputs_mut()[1].script_pubkey = op_return();
        for i in 0..2 {
            // make sure we don't blind the covenant outputs by removing blinding details
            self.outputs_mut()[i].blinding_key = None;
            self.outputs_mut()[i].blinder_index = None;
        }
        // No timelocks to set in cancellation
        pset_add_cov(self, secp, &user_params, &contract, coll_desc, None, cov_ty)?;
        Ok(())
    }

    fn expiry_contract(
        &mut self,
        secp: &Secp256k1<secp256k1::All>,
        contract: OptionsContract,
        user_params: &CovUserParams,
    ) -> Result<(), Error> {
        // Check the pre-conditions
        let crt_burn_out = self.outputs().get(0).ok_or(Error::MissingPsetOutput(0))?;
        if crt_burn_out.asset != Some(contract.crt()) {
            return Err(Error::IncorrectCovAsset {
                exp_asset: contract.crt(),
                got_asset: crt_burn_out.asset.ok_or(Error::MissingOutputAssetId(0))?,
                name: "Expiry: CRT output",
                pos: 0,
            });
        }
        if crt_burn_out.amount != Some(user_params.num_contracts) {
            return Err(Error::IncorrectCovAmount {
                exp_amount: user_params.num_contracts,
                got_amount: crt_burn_out.amount.ok_or(Error::MissingOutputAmount(0))?,
                name: "Expiry: CRT output",
                pos: 0,
            });
        }

        let desc = contract.coll_desc();
        let cov_ty = UserCovType::Collateral;
        cov_input_checks(user_params, &contract, &desc, cov_ty)?;

        // Preconditions checked
        // ---------------------------------------
        self.outputs_mut()[0].script_pubkey = op_return();
        // make sure we don't blind the covenant outputs by removing blinding details
        self.outputs_mut()[0].blinding_key = None;
        self.outputs_mut()[0].blinder_index = None;
        // No timelocks to set in cancellation
        let locktime = Some(contract.params().expiry);
        pset_add_cov(self, secp, &user_params, &contract, desc, locktime, cov_ty)?;
        Ok(())
    }

    fn settle_contract(
        &mut self,
        secp: &Secp256k1<secp256k1::All>,
        contract: OptionsContract,
        user_params: &CovUserParams,
    ) -> Result<(), Error> {
        // Check the pre-conditions
        let crt_burn_out = self.outputs().get(0).ok_or(Error::MissingPsetOutput(0))?;
        if crt_burn_out.asset != Some(contract.crt()) {
            return Err(Error::IncorrectCovAsset {
                exp_asset: contract.crt(),
                got_asset: crt_burn_out.asset.ok_or(Error::MissingOutputAssetId(0))?,
                name: "Settlement: CRT output",
                pos: 0,
            });
        }
        if crt_burn_out.amount != Some(user_params.num_contracts) {
            return Err(Error::IncorrectCovAmount {
                exp_amount: user_params.num_contracts,
                got_amount: crt_burn_out.amount.ok_or(Error::MissingOutputAmount(0))?,
                name: "Settlement: CRT output",
                pos: 0,
            });
        }

        let desc = contract.settle_desc();
        let cov_ty = UserCovType::Settlement;
        cov_input_checks(user_params, &contract, &desc, cov_ty)?;

        // Preconditions checked
        // ---------------------------------------
        self.outputs_mut()[0].script_pubkey = op_return();
        // make sure we don't blind the covenant outputs by removing blinding details
        self.outputs_mut()[0].blinding_key = None;
        self.outputs_mut()[0].blinder_index = None;
        // No timelocks to set in cancellation
        pset_add_cov(self, secp, &user_params, &contract, desc, None, cov_ty)?;
        Ok(())
    }
}

/// User facing covenant contracts
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Ord, Eq, Hash)]
enum UserCovType {
    /// Collateral covenant
    Collateral,
    /// Settlement covenant
    Settlement,
}

// Common checks on collateral inputs shared across options contract operations
fn cov_input_checks(
    user_params: &CovUserParams,
    contract: &OptionsContract,
    desc: &TrDesc,
    cov_type: UserCovType,
) -> Result<(), Error> {
    let (err_str, contract_multiplier, cov_asset) = match cov_type {
        UserCovType::Collateral => (
            "Collateral Input",
            contract.params().contract_size,
            contract.params().coll_asset,
        ),
        UserCovType::Settlement => (
            "Settlement Input",
            contract.params().strike_price,
            contract.params().settle_asset,
        ),
    };
    let cov_utxo = &user_params.cov_prevout.1;
    let in_asset = cov_utxo.asset.explicit();
    let in_value = cov_utxo.value.explicit();
    if in_asset != Some(cov_asset) {
        return Err(Error::IncorrectCovAsset {
            exp_asset: cov_asset,
            got_asset: in_asset.ok_or(Error::MissingInputAssetId(0))?,
            name: err_str,
            pos: 1,
        });
    }
    // Not sure what behavior do we want here. For now, we error if the input covenant
    // does not have enough contracts
    let dest_amt = user_params.num_contracts * contract_multiplier;
    let cov_in_amt = in_value.ok_or(Error::MissingInputAmount(0))?;
    if cov_in_amt < dest_amt {
        return Err(Error::InsufficientAmount {
            requested_amount: dest_amt,
            avail_amount: cov_in_amt,
            name: err_str,
            pos: 0,
        });
    }

    if &desc.script_pubkey() != &cov_utxo.script_pubkey {
        return Err(Error::IncorrectCovSpk {
            exp_spk: desc.script_pubkey(),
            got_spk: cov_utxo.script_pubkey.clone(),
            name: err_str,
            pos: 0,
        });
    }
    Ok(())
}

/// Helper function for de-duplicating the code across various spend paths
/// 1) Adds the collateral input at input position 0
/// 2) Adds the change collateral(if present) at output position 2
/// 3) Sends the unlocked collateral to the specified address.
/// 4) Satisfies and finalizes the covenant input at position 0.
///
/// At a high level, This takes in previously balanced pset and adds one collateral input
/// and two outputs 1) Change(if required) 2) unlocked collateral output
fn pset_add_cov(
    pset: &mut Pset,
    secp: &Secp256k1<All>,
    user_params: &CovUserParams,
    contract: &OptionsContract,
    cov_desc: TrDesc,
    req_locktime: Option<u32>,
    cov_type: UserCovType,
) -> Result<(), Error> {
    let (contract_multiplier, cov_asset) = match cov_type {
        UserCovType::Collateral => (
            contract.params().contract_size,
            contract.params().coll_asset,
        ),
        UserCovType::Settlement => (
            contract.params().strike_price,
            contract.params().settle_asset,
        ),
    };
    let mut inp = pset::Input::default();
    inp.previous_txid = user_params.cov_prevout.0.txid;
    inp.previous_output_index = user_params.cov_prevout.0.vout;
    inp.witness_utxo = Some(user_params.cov_prevout.1.clone());
    if let Some(req_locktime) = req_locktime {
        let lt =
            locktime::Time::from_consensus(req_locktime).map_err(|e| Error::InvalidLocktime(e))?;
        inp.required_time_locktime = Some(lt); // set the required time as start
        inp.sequence = Some(elements::Sequence(u32::MAX - 1)); // set to max - 1 in order to timelocks
    }
    pset.insert_input(inp, 0);

    // set the correct destinations
    let dest_amt = user_params.num_contracts * contract_multiplier;
    let in_value = user_params.cov_prevout.1.value.explicit();
    let totol_in = in_value.ok_or(Error::MissingInputAmount(0))?;
    let change_amt = totol_in - dest_amt;
    if change_amt > 0 {
        let mut out = pset::Output::default();
        out.amount = Some(change_amt);
        out.asset = Some(cov_asset);
        out.script_pubkey = cov_desc.script_pubkey();
        pset.insert_output(out, 2);
    }
    let mut out = pset::Output::default();
    out.amount = Some(dest_amt);
    out.script_pubkey = user_params.dest_addr.script_pubkey();
    out.asset = Some(cov_asset);
    if let Some(key) = user_params.dest_addr.blinding_pubkey {
        out.blinding_key = Some(PublicKey::new(key));
        // blinders shifted by one as we added one input
        out.blinder_index = Some(1);
    }

    pset.add_output(out);
    let coll_desc = translate_xpk_desc_pubkey(cov_desc);
    pset.update_input_with_descriptor(0, &coll_desc)
        .map_err(|e| Error::UtxoUpdate(0, e))?;
    // There are no signatures here, so we can use default blockhash
    // If we add sigs to covenant, we would also need to pass the genesis hash here
    pset.finalize_inp_mall_mut(secp, 0, BlockHash::all_zeros())
        .map_err(|e| Error::Finalize(0, e))?;
    Ok(())
}

/// Helper function to compute txout secrets by rewinding the rangeproofs
fn pset_txout_secrets(
    pset: &Pset,
    secp: &Secp256k1<All>,
    blinding_sks: &HashMap<usize, secp256k1::SecretKey>,
) -> Result<HashMap<usize, TxOutSecrets>, Error> {
    let mut txout_secrets = HashMap::new();
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
    /// Blinding error
    BlindError(BlindError),
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
    /// Pset blinding errors
    PsetBlind(PsetBlindError),
    /// Miniscript errors
    MsError(miniscript::Error),
    /// Incorrect asset at index
    IncorrectCovAmount {
        /// Expected amount
        exp_amount: u64,
        /// Got amount
        got_amount: u64,
        /// Name of covenant: Coll/Settlement ..
        name: &'static str,
        /// The output position of the covenant
        pos: usize,
    },
    /// Incorrect amount at index
    IncorrectCovAsset {
        /// Expected amount
        exp_asset: AssetId,
        /// Got amount
        got_asset: AssetId,
        /// Name of covenant: Coll/Settlement ..
        name: &'static str,
        /// The output position of the covenant
        pos: usize,
    },
    /// Incorrect covenant Spk
    IncorrectCovSpk {
        /// Expected amount
        exp_spk: Script,
        /// Got amount
        got_spk: Script,
        /// Name of covenant: Coll/Settlement ..
        name: &'static str,
        /// The output position of the covenant
        pos: usize,
    },
    /// Insufficient funding amount
    InsufficientAmount {
        /// Expected amount
        requested_amount: u64,
        /// Got amount
        avail_amount: u64,
        /// Name of covenant: Coll/Settlement ..
        name: &'static str,
        /// The output position of the covenant
        pos: usize,
    },
    /// Missing explicit output asset
    MissingOutputAssetId(usize),
    /// Missing explicit output asset
    MissingOutputAmount(usize),
    /// Missing explicit input asset
    MissingInputAssetId(usize),
    /// Missing explicit input asset
    MissingInputAmount(usize),
    /// Utxo update error
    UtxoUpdate(usize, UtxoUpdateError),
    /// Finalize error
    Finalize(usize, miniscript::psbt::Error),
    /// Conversion error from UNIX timestamp to locktime
    InvalidLocktime(elements::locktime::Error),
}

impl From<miniscript::Error> for Error {
    fn from(v: miniscript::Error) -> Self {
        Self::MsError(v)
    }
}

impl From<PsetBlindError> for Error {
    fn from(v: PsetBlindError) -> Self {
        Self::PsetBlind(v)
    }
}

impl From<BlindError> for Error {
    fn from(v: BlindError) -> Self {
        Self::BlindError(v)
    }
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
            | Error::MissingOutputAmount(_)
            | Error::MissingOutputAssetId(_)
            | Error::MissingInputAmount(_)
            | Error::MissingInputAssetId(_)
            | Error::MissingPsetOutput(_)
            | Error::IncorrectCovAsset { .. }
            | Error::IncorrectCovAmount { .. }
            | Error::InsufficientAmount { .. }
            | Error::IncorrectCovSpk { .. }
            | Error::UtxoSecretLenMismatch => None,
            Error::UnBlindError(e, _i) => Some(e),
            Error::InvalidLocktime(_e) => None, // This should be some, but guarded by std clause in rust-elements
            Error::PsetBlind(e) => Some(e),
            Error::BlindError(e) => Some(e),
            Error::PsetError(e) => Some(e),
            Error::Secp(e) => Some(e),
            Error::MsError(e) => Some(e),
            Error::UtxoUpdate(_, e) => Some(e),
            Error::Finalize(_, e) => Some(e),
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
            Error::IncorrectCovAsset {
                exp_asset,
                got_asset,
                name,
                pos,
            } => write!(
                f,
                "{} Covenant: Asset does not match at index {}. Expected {}, got: {}",
                name, pos, exp_asset, got_asset
            ),
            Error::IncorrectCovAmount {
                exp_amount,
                got_amount,
                name,
                pos,
            } => write!(
                f,
                "{} Covenant: amount does not match at index {}. Expected {}, got: {}",
                name, pos, exp_amount, got_amount
            ),
            Error::IncorrectCovSpk {
                exp_spk,
                got_spk,
                name,
                pos,
            } => write!(
                f,
                "{} Covenant: spk does not match at index {}. Expected {:x}, got: {:x}",
                name, pos, exp_spk, got_spk
            ),
            Error::InsufficientAmount {
                requested_amount,
                avail_amount,
                name,
                pos,
            } => write!(
                f,
                "{} Covenant: insufficient funding amount at index {}. Requested {}, Available: {}",
                name, pos, requested_amount, avail_amount
            ),
            Error::BlindError(_e) => write!(f, "Blinding error"),
            Error::PsetBlind(_e) => write!(f, "Pset blinding error"),
            Error::MsError(_e) => write!(f, "Miniscript error"),
            Error::MissingOutputAssetId(i) => write!(f, "Missing explicit output asset at {}", i),
            Error::MissingOutputAmount(i) => write!(f, "Missing explicit output amount at {}", i),
            Error::MissingInputAssetId(i) => write!(f, "Missing explicit input asset at {}", i),
            Error::MissingInputAmount(i) => write!(f, "Missing explicit input amount at {}", i),
            Error::UtxoUpdate(i, _e) => write!(f, "Utxo update error at index {}", i),
            Error::Finalize(i, _e) => write!(f, "Finalize error at index {}", i),
            Error::InvalidLocktime(e) => write!(f, "Invalid locktime: {}", e),
        }
    }
}
