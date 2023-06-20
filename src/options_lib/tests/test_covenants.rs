//! # rust-miniscript integration test
//!
//! Arith expression fragment integration tests
//!

use std::collections::BTreeMap;
use std::str::FromStr;

use elements::encode::serialize_hex;
use elements::hashes::Hash;
use elements::pset::PartiallySignedTransaction as Psbt;
use elements::{pset as psbt, OutPoint, TxOut, Txid, ContractHash};
use elements_miniscript as miniscript;
use elementsd::bitcoincore_rpc::jsonrpc::base64;
use elementsd::bitcoincore_rpc::jsonrpc::serde_json::json;
use elementsd::ElementsD;
use miniscript::bitcoin;
use miniscript::bitcoin::Amount;
use miniscript::elements::confidential::{AssetBlindingFactor, ValueBlindingFactor};
use miniscript::elements::encode::deserialize;
use miniscript::elements::hashes::hex::FromHex;
use miniscript::elements::secp256k1_zkp::rand::thread_rng;
use miniscript::elements::secp256k1_zkp::Secp256k1;
use miniscript::elements::{self, AddressParams, AssetId, Script, TxOutSecrets};
use options_lib::OptionsExt;
mod setup;
use options_lib::contract::{CovUserParams, FundingParams};
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
            .to_sat(),
            asset: AssetId::from_hex(&v["asset"].as_str().unwrap()).unwrap(),
        };
        ret.push((inp, secrets));
        if ret.len() == count {
            return ret;
        }
    }
    panic!("Cannot fund pset with two seperate utxos: Wallet must have atleast two utxos")
}

fn _get_pset_txout_secrets(cl: &ElementsD, pset: &Psbt) -> BTreeMap<usize, TxOutSecrets> {
    let value = cl.call("listunspent", &[]);
    let mut ret = BTreeMap::new();
    // This can be more efficient that a 2d loop, but we don't care as of now
    for (i, inp) in pset.inputs().iter().enumerate() {
        for v in value.as_array().unwrap() {
            let prev_txid = Txid::from_str(&v["txid"].as_str().unwrap()).unwrap();
            let prev_vout = v["vout"].as_u64().unwrap() as u32;
            if !(inp.previous_txid == prev_txid && inp.previous_output_index == prev_vout) {
                continue;
            }
            let secrets = TxOutSecrets {
                asset_bf: AssetBlindingFactor::from_str(&v["assetblinder"].as_str().unwrap())
                    .unwrap(),
                value_bf: ValueBlindingFactor::from_str(&v["amountblinder"].as_str().unwrap())
                    .unwrap(),
                value: bitcoin::Amount::from_float_in(
                    v["amount"].as_f64().unwrap(),
                    bitcoin::Denomination::Bitcoin,
                )
                .unwrap()
                .to_sat(),
                asset: AssetId::from_hex(&v["asset"].as_str().unwrap()).unwrap(),
            };
            ret.insert(i, secrets);
        }
        if ret.len() != (i + 1) {
            panic!("Non-wallet input found");
        }
    }
    ret
}

pub fn funded_pset(cl: &ElementsD, btc_asset: AssetId) -> (Psbt, BTreeMap<usize, TxOutSecrets>) {
    let unspent = get_unspent(cl, btc_asset, 2);
    let mut pset = Psbt::new_v2();
    let mut in_total = 0u64;
    let mut secrets = BTreeMap::new();
    for (i, (inp, secret)) in unspent.into_iter().enumerate() {
        pset.add_input(inp);
        in_total += secret.value;
        secrets.insert(i, secret);
    }
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

fn swap_pset(pset: &mut Psbt, target_pos: usize, asset: AssetId, spk: &Script) {
    let i = pset
        .outputs()
        .iter()
        .position(|o| o.asset == Some(asset) && &o.script_pubkey == spk);
    pset.outputs_mut()
        .swap(target_pos, i.expect("Must have fund txout"));
}

#[test]
#[rustfmt::skip]
fn test_covenants() {
    let (cl, _, _genesis_hash, btc_asset_id) = &setup::setup(false);
    let usd_asset = setup_wallet(cl);
    let (pset, _txout_secrets) = funded_pset(cl, *btc_asset_id);

    let mut pset = cl.utxo_update_psbt(&pset);
    let opt_params = options_lib::BaseParams {
        contract_size: 1000_000,
        expiry: 1659127125, // timestamp ~friday 2pm PST
        start: 1659141525,  // timestamp ~friday 11am PST
        strike_price: 500,
        coll_asset: *btc_asset_id,
        settle_asset: usd_asset,
        contract_hash: ContractHash::hash("data".as_bytes()),
    };
    let secp = Secp256k1::new();

    let contract = pset
        .issue_rts(&secp, &mut thread_rng(), opt_params)
        .unwrap();

    let pset = cl.wallet_process_psbt(&pset, true);

    let issue_tx = cl.finalize_psbt(&pset);
    let issue_txid = cl.send_raw_transaction(&issue_tx);
    cl.generate(6);
    assert!(cl.get_num_confirmations(issue_txid) > 0);

    // let issue_tx: Transaction =
    //     deserialize(&Vec::<u8>::from_hex(res["hex"].as_str().unwrap()).unwrap()).unwrap();
    // assert!(cl.test_mempool_accept(&issue_tx));
    // let issue_txid = cl.send_raw_transaction(&issue_tx);

    //------------------------------- RT tokens issued---------------------------
    let crt_addr = cl.get_new_address();
    let ort_addr = cl.get_new_address();
    let fund_params = FundingParams {
        crt_prevout: (OutPoint::new(issue_txid, 2), issue_tx.output[2].clone()),
        ort_prevout: (OutPoint::new(issue_txid, 3), issue_tx.output[3].clone()),
        num_contracts: 10,
        ort_dest_addr: crt_addr,
        crt_dest_addr: ort_addr,
    };

    let cov_addr = contract.coll_desc().address(None, &AddressParams::ELEMENTS);
    cl.generate(1);
    let value = cl.call(
        "walletcreatefundedpsbt",
        &[
            json!([]),
            json!([
                {cov_addr.to_string(): "0.1", "asset": btc_asset_id.to_string()},
            ]),
        ],
    );
    let pset_base64 = value["psbt"].as_str().unwrap().to_string();
    let mut pset : Psbt = deserialize(&base64::decode(&pset_base64).unwrap()).unwrap();

    swap_pset(&mut pset, 0, *btc_asset_id, &cov_addr.script_pubkey());

    // let mut txout_secrets = get_pset_txout_secrets(cl, &pset);
    // pset.fund_contract_with_blinds(&secp, &mut thread_rng(), contract, &mut txout_secrets, &fund_params).unwrap();


    // let tx = pset.extract_tx().unwrap();
    // let res = cl.call(
    //     "signrawtransactionwithwallet",
    //     &[serialize(&tx).to_hex().into()],
    // );

    // let fund_tx: Transaction =
    //     deserialize(&Vec::<u8>::from_hex(res["hex"].as_str().unwrap()).unwrap()).unwrap();

    pset.fund_contract(&secp, &mut thread_rng(), contract, &fund_params).unwrap();
    let pset = cl.wallet_process_psbt(&pset, true);

    let fund_tx = cl.finalize_psbt(&pset);
    println!("{}", serialize_hex(&fund_tx));
    // assert!(cl.test_mempool_accept(&fund_tx));
    let fund_txid = cl.send_raw_transaction(&fund_tx);
    cl.generate(6);
    assert!(cl.get_num_confirmations(fund_txid) > 0);

    // 10 contracts funded.
    // --------------- Covenants-funded. Testing exercise (with change)

    let coll_claim_addr = cl.get_new_address();
    let exercise_params = CovUserParams {
        cov_prevout: (OutPoint::new(fund_txid, 2), fund_tx.output[2].clone()),
        num_contracts: 3, // only exercise 3 contracts
        dest_addr: coll_claim_addr,
    };
    let dummy_addr = cl.get_new_address();
    let dummy_addr2 = cl.get_new_address();

    let value = cl.call(
        "walletcreatefundedpsbt",
        &[
            json!([]),
            json!([
                {dummy_addr.to_string(): "0.000015", "asset": usd_asset.to_string()},
                {dummy_addr2.to_string(): "0.00000003", "asset": contract.ort().to_string()},
            ]),
        ],
    );
    let pset_base64 = value["psbt"].as_str().unwrap().to_string();
    let mut pset : Psbt = deserialize(&base64::decode(&pset_base64).unwrap()).unwrap();
    swap_pset(&mut pset, 1, usd_asset, &dummy_addr.script_pubkey());
    swap_pset(&mut pset, 0, contract.ort(), &dummy_addr2.script_pubkey());
    // pset.global.tx_data.fallback_locktime = Some(PackedLockTime(1659141525 + 60 * 60 * 1)); // 1 hour after start

    pset.exercise_contract(&secp, contract, &exercise_params).unwrap();

    let pset = cl.wallet_process_psbt(&pset, true);

    let exercise_tx = cl.finalize_psbt(&pset);
    let exercise_txid = cl.send_raw_transaction(&exercise_tx);
    cl.generate(6);
    assert!(cl.get_num_confirmations(exercise_txid) > 0);


    // 10 contracts funded of which 3 exercised. 7 remaining
    // 3 settlement covenants remaining
    // -------------------------------- Cancellation (with change)
    let coll_claim_addr = cl.get_new_address();
    let cancel_params = CovUserParams {
        cov_prevout: (OutPoint::new(exercise_txid, 2), exercise_tx.output[2].clone()),
        num_contracts: 4, // only cancel 4 contracts
        dest_addr: coll_claim_addr,
    };
    let dummy_addr = cl.get_new_address();
    let dummy_addr2 = cl.get_new_address();

    let value = cl.call(
        "walletcreatefundedpsbt",
        &[
            json!([]),
            json!([
                {dummy_addr.to_string(): "0.00000004", "asset": contract.crt().to_string()},
                {dummy_addr2.to_string(): "0.00000004", "asset": contract.ort().to_string()},
            ]),
        ],
    );

    let pset_base64 = value["psbt"].as_str().unwrap().to_string();
    let mut pset : Psbt = deserialize(&base64::decode(&pset_base64).unwrap()).unwrap();
    swap_pset(&mut pset, 0, contract.crt(), &dummy_addr.script_pubkey());
    swap_pset(&mut pset, 1, contract.ort(), &dummy_addr2.script_pubkey());

    pset.cancel_contract(&secp, contract, &cancel_params).unwrap();

    let pset = cl.wallet_process_psbt(&pset, true);
    let tx = cl.finalize_psbt(&pset);
    let txid = cl.send_raw_transaction(&tx);
    cl.generate(6);
    assert!(cl.get_num_confirmations(txid) > 0);

    // 10 contracts funded of which 3 exercised. 4 cancelled, 3 remaining
    // 3 settlement covenants remaining
    //----------------- Expiry(without change)

    let coll_claim_addr = cl.get_new_address();
    let expiry_params = CovUserParams {
        cov_prevout: (OutPoint::new(txid, 2), tx.output[2].clone()),
        num_contracts: 3, // expire the three remaining contracts. No change output
        dest_addr: coll_claim_addr,
    };
    let dummy_addr = cl.get_new_address();

    let value = cl.call(
        "walletcreatefundedpsbt",
        &[
            json!([]),
            json!([
                {dummy_addr.to_string(): "0.00000003", "asset": contract.crt().to_string()},
            ]),
        ],
    );

    let pset_base64 = value["psbt"].as_str().unwrap().to_string();
    let mut pset : Psbt = deserialize(&base64::decode(&pset_base64).unwrap()).unwrap();
    swap_pset(&mut pset, 0, contract.crt(), &dummy_addr.script_pubkey());
    // pset.global.tx_data.fallback_locktime = Some(PackedLockTime(1659127125 + 60 * 60 * 1)); // 1 hour after expiry

    pset.expiry_contract(&secp, contract, &expiry_params).unwrap();

    let pset = cl.wallet_process_psbt(&pset, true);
    let tx = cl.finalize_psbt(&pset);
    let txid = cl.send_raw_transaction(&tx);
    cl.generate(6);
    assert!(cl.get_num_confirmations(txid) > 0);

    // 10 contracts funded of which 3 exercised. 4 cancelled, 3 expired, 0 remaining
    // 3 settlement covenants remaining
    // ---------------- Settlement with change

    let settle_claim_addr = cl.get_new_address();
    let settle_params = CovUserParams {
        cov_prevout: (OutPoint::new(exercise_txid, 1), exercise_tx.output[1].clone()),
        num_contracts: 1, // Only settle on one contract
        dest_addr: settle_claim_addr,
    };
    let dummy_addr = cl.get_new_address();

    let value = cl.call(
        "walletcreatefundedpsbt",
        &[
            json!([]),
            json!([
                {dummy_addr.to_string(): "0.00000001", "asset": contract.crt().to_string()},
            ]),
        ],
    );

    let pset_base64 = value["psbt"].as_str().unwrap().to_string();
    let mut pset : Psbt = deserialize(&base64::decode(&pset_base64).unwrap()).unwrap();
    swap_pset(&mut pset, 0, contract.crt(), &dummy_addr.script_pubkey());

    pset.settle_contract(&secp, contract, &settle_params).unwrap();

    let pset = cl.wallet_process_psbt(&pset, true);
    let tx = cl.finalize_psbt(&pset);
    let txid = cl.send_raw_transaction(&tx);
    cl.generate(6);
    assert!(cl.get_num_confirmations(txid) > 0);

    // 10 contracts funded of which 3 exercised. 4 cancelled, 3 expired, 0 remaining
    // 1 settlement covenants claimed, 2 remaining
    // ------------------------- Settlement with no change

    let settle_claim_addr = cl.get_new_address();
    let settle_params = CovUserParams {
        cov_prevout: (OutPoint::new(txid, 2), tx.output[2].clone()),
        num_contracts: 2, // Settle the remaining two contracts: no change
        dest_addr: settle_claim_addr,
    };
    let dummy_addr = cl.get_new_address();

    let value = cl.call(
        "walletcreatefundedpsbt",
        &[
            json!([]),
            json!([
                {dummy_addr.to_string(): "0.00000002", "asset": contract.crt().to_string()},
            ]),
        ],
    );

    let pset_base64 = value["psbt"].as_str().unwrap().to_string();
    let mut pset : Psbt = deserialize(&base64::decode(&pset_base64).unwrap()).unwrap();
    swap_pset(&mut pset, 0, contract.crt(), &dummy_addr.script_pubkey());

    pset.settle_contract(&secp, contract, &settle_params).unwrap();

    let pset = cl.wallet_process_psbt(&pset, true);
    let tx = cl.finalize_psbt(&pset);
    let txid = cl.send_raw_transaction(&tx);
    cl.generate(6);
    assert!(cl.get_num_confirmations(txid) > 0);
    // 10 contracts funded of which 3 exercised. 4 cancelled, 3 expired, 0 remaining
    // Everything claimed, no change
    // ------------------------- Settlement with no change
}
