//! # rust-miniscript integration test
//!
//! Arith expression fragment integration tests
//!

use std::str::FromStr;

use elements_miniscript as miniscript;
use elementsd::bitcoincore_rpc::jsonrpc::base64;
use miniscript::bitcoin::Amount;
use miniscript::elements::confidential::{AssetBlindingFactor, ValueBlindingFactor};
use miniscript::elements::encode::{deserialize, serialize, serialize_hex};
use miniscript::elements::hashes::hex::{FromHex, ToHex};
use miniscript::elements::secp256k1_zkp::rand::thread_rng;
use miniscript::elements::secp256k1_zkp::Secp256k1;
use miniscript::elements::{self, AssetId, Transaction, TxOutSecrets};

use elements::pset::PartiallySignedTransaction as Psbt;
use elements::{pset as psbt, OutPoint, TxOut, Txid};
use elementsd::ElementsD;
use miniscript::bitcoin;
use options::OptionsExt;
mod setup;
use setup::Call;

fn get_unspent(
    cl: &ElementsD,
    asset_id: AssetId,
    count: usize,
) -> Vec<(psbt::Input, TxOutSecrets)> {
    let value = cl.call("listunspent", &[]);
    let mut ret = vec![];
    for v in value.as_array().unwrap() {
        if &v["asset"].as_str().unwrap() != &asset_id.to_string() {
            // Only look for utxos of a certain asset
            continue;
        }
        let inp = psbt::Input::from_prevout(OutPoint::new(
            Txid::from_str(&v["txid"].as_str().unwrap()).unwrap(),
            v["vout"].as_u64().unwrap() as u32,
        ));
        let secrets = TxOutSecrets {
            asset_bf: AssetBlindingFactor::from_str(&v["assetblinder"].as_str().unwrap()).unwrap(),
            value_bf: ValueBlindingFactor::from_str(&v["amountblinder"].as_str().unwrap()).unwrap(),
            value: bitcoin::Amount::from_float_in(
                v["amount"].as_f64().unwrap(),
                bitcoin::Denomination::Bitcoin,
            )
            .unwrap()
            .as_sat(),
            asset: AssetId::from_hex(&v["asset"].as_str().unwrap()).unwrap(),
        };
        ret.push((inp, secrets));
        if ret.len() == count {
            return ret;
        }
    }
    panic!("Cannot fund pset with two seperate utxos: Wallet must have atleast two utxos")
}

pub fn funded_pset(cl: &ElementsD, btc_asset: AssetId) -> (Psbt, Vec<TxOutSecrets>) {
    let unspent = get_unspent(cl, btc_asset, 2);
    let mut pset = Psbt::new_v2();
    let mut in_total = 0u64;
    let mut secrets = vec![];
    for (inp, secret) in unspent {
        pset.add_input(inp);
        in_total += secret.value;
        secrets.push(secret);
    }
    dbg!(in_total);
    let fees = 1_000; // random fixed value for fees.
    let btc_fees_txout = TxOut::new_fee(fees, btc_asset);

    let addr = cl.get_new_address();
    let mut dest_txout =
        psbt::Output::new_explicit(addr.script_pubkey(), in_total - fees, btc_asset, None);
    dest_txout.blinding_key = addr.blinding_pubkey.map(bitcoin::PublicKey::new);
    dest_txout.blinder_index = Some(0);

    pset.add_output(dest_txout);
    pset.add_output(psbt::Output::from_txout(btc_fees_txout));

    let updated_pset = cl.utxo_update_psbt(&pset);
    (updated_pset, secrets)
}

// The options pset requires atleast two utxos in the wallet
// Outputs a new issued asset used for settlement asset
fn setup_wallet(cl: &ElementsD) -> AssetId {
    // make some dummy transactions to create multiple utxos
    for _i in 0..5 {
        let addr = cl.get_new_address();
        cl.send_to_address(&addr, bitcoin::Amount::from_sat(100_000));
        cl.generate(1);
    }
    // Issue some asset for settlement asset
    let (settle_asset, _) = cl.issue_asset(Amount::ONE_BTC, Amount::ZERO, false);
    cl.generate(6); // some confirmations
    settle_asset
}

#[test]
#[rustfmt::skip]
fn test_arith() {
    let (cl, _, _genesis_hash, btc_asset_id) = &setup::setup(false);
    let usd_asset = setup_wallet(cl);
    let (pset, txout_secrets) = funded_pset(cl, *btc_asset_id);

    println!("{}", base64::encode(&serialize(&pset)));
    let mut pset = cl.utxo_update_psbt(&pset);
    // let pset2 = cl.wallet_process_psbt(&pset, /*sign*/ true);
    println!("{}", base64::encode(&serialize(&pset)));
    let opt_params = options::BaseParams {
        contract_size: 10,
        expiry: 1659127125, // timestamp ~friday 2pm PST
        start: 1659141525,  // timestamp ~friday 11am PST
        strike_price: 50_000,
        coll_asset: *btc_asset_id,
        settle_asset: usd_asset,
    };
    let secp = Secp256k1::new();

    let _contract = pset
        .issue_rts(&secp, &mut thread_rng(), opt_params, &txout_secrets)
        .unwrap();
    // pset.outputs_mut()[2].blinder_index = Some(0);
    // pset.outputs_mut()[3].blinder_index = Some(0);

    // pset.outputs_mut()[2].blinding_key = pset.outputs_mut()[0].blinding_key;
    // pset.outputs_mut()[3].blinding_key = pset.outputs_mut()[0].blinding_key;

    println!("{}", base64::encode(&serialize(&pset)));
    let mut tx = pset.extract_tx().unwrap();
    // testing scope
    // {
    //     tx.input.push(tx.input[0].clone());
    //     tx.input.push(tx.input[1].clone());
    //     tx.input.swap(1, 2);

    //     let mut spent_utxos = [
    //         pset.inputs()[0].witness_utxo.as_ref().unwrap().clone(),
    //         pset.inputs()[0].witness_utxo.as_ref().unwrap().clone(),
    //         pset.inputs()[1].witness_utxo.as_ref().unwrap().clone(),
    //         pset.inputs()[1].witness_utxo.as_ref().unwrap().clone(),
    //     ];

    //     // we don't care about nonce/spk and txoutwitness
    //     spent_utxos[1].asset = confidential::Asset::Explicit(contract.crt_rt());
    //     spent_utxos[1].value = confidential::Value::Explicit(1);

    //     spent_utxos[3].asset = confidential::Asset::Explicit(contract.ort_rt());
    //     spent_utxos[3].value = confidential::Value::Explicit(1);

    //     println!("{}", &serialize(&tx).to_hex());
    //     assert_eq!(confidential::Asset::new_confidential(&secp, spent_utxos[1].asset.explicit().unwrap(), AssetBlindingFactor::one()), tx.output[2].asset);
    //     assert_eq!(confidential::Asset::new_confidential(&secp, spent_utxos[3].asset.explicit().unwrap(), AssetBlindingFactor::one()), tx.output[3].asset);
    //     assert_eq!(spent_utxos[1].value, tx.output[2].value);
    //     assert_eq!(spent_utxos[3].value, tx.output[3].value);
    //     tx.verify_tx_amt_proofs(&secp, &spent_utxos).unwrap();
    // }
    // dbg!(&tx.input);
    tx.input[0].has_issuance = true;
    tx.input[1].has_issuance = true;
    let res = cl.call(
        "signrawtransactionwithwallet",
        &[serialize(&tx).to_hex().into()],
    );
    println!("{}", serialize_hex(&tx));
    let tx: Transaction =
        deserialize(&Vec::<u8>::from_hex(res["hex"].as_str().unwrap()).unwrap()).unwrap();
    // assert!(cl.test_mempool_accept(&tx));
    // cl.send_raw_transaction(&tx);

    // try to verify the surjection proof here
    // {
    //     let prf = tx.output[0].witness.surjection_proof.as_ref().unwrap();
    //     let mut domain = vec![];
    //     domain.push(pset.inputs()[0].witness_utxo.as_ref().unwrap().asset.commitment().unwrap());
    //     domain.push(Generator::new_unblinded(&secp, contract.crt_rt().into_tag()));
    //     domain.push(pset.inputs()[1].witness_utxo.as_ref().unwrap().asset.commitment().unwrap());
    //     domain.push(Generator::new_unblinded(&secp, contract.ort_rt().into_tag()));

    //     SurjectionProof::new(&secp, &mut thread_rng(), btc_asset_id , codomain_blinding_factor, domain);
    //     assert!(prf.verify(&secp, tx.output[0].asset.commitment().unwrap(), &domain));
    // }
    // cl.test_mempool_accept(&tx);
    let txid = cl.send_raw_transaction(&tx);
    cl.generate(1);
    println!("{}", serialize_hex(&tx));
    dbg!(cl.call(
        "gettransaction",
        &[txid.to_hex().into()],
    ));
    // println!("{}", base64::encode(&serialize(&pset)));
    // let pset = cl.wallet_process_psbt(&pset, /*sign*/ true);
    // println!("{}", base64::encode(&serialize(&pset)));
    // let mut tx = pset.extract_tx().unwrap();
    // tx.input[0].has_issuance = true;
    // tx.input[1].has_issuance = true;

    // println!("{}", serialize_hex(&tx));
    // // assert!(cl.test_mempool_accept(&tx));
    // cl.send_raw_transaction(&tx);
}
