//! Module defining the RPC interface for the `elementsd` server.
//!

use std::str::FromStr;

use elementsd::bitcoincore_rpc::bitcoin::hashes::hex::FromHex;
use elementsd::bitcoincore_rpc::bitcoin::secp256k1::rand::thread_rng;
use elementsd::bitcoincore_rpc::jsonrpc::base64;
use elementsd::bitcoincore_rpc::jsonrpc::error::RpcError;
use elementsd::bitcoincore_rpc::Client;
use options_lib::contract::{CovUserParams, FundingParams};
use options_lib::cov_scripts::TrDesc;
use options_lib::miniscript::elements;
use options_lib::miniscript::elements::encode::{deserialize, serialize, serialize_hex};
use options_lib::miniscript::elements::pset::PartiallySignedTransaction as Pset;
use options_lib::miniscript::elements::{
    bitcoin, confidential, AssetId, OutPoint, Script, Transaction, TxOut, TxOutWitness, Txid,
};
use options_lib::{pset, BaseParams, OptionsContract, OptionsExt};
use secp256k1::hashes::hex::ToHex;
use secp256k1::SECP256K1;
use serde_json::{json, Value};

use crate::contract::OptionsBook;
use crate::data_structures::{ContractArgs, InitArgs, NetworkParams, QueryResponse};

pub trait OptionOps {
    fn initialize(
        &self,
        _net: &NetworkParams,
        _args: &InitArgs,
        book: &mut OptionsBook,
    ) -> QueryResponse;

    fn fund(
        &self,
        _net: &NetworkParams,
        _args: &ContractArgs,
        _book: &OptionsBook,
    ) -> QueryResponse;

    fn exercise(
        &self,
        _net: &NetworkParams,
        _args: &ContractArgs,
        _book: &OptionsBook,
    ) -> QueryResponse;

    fn cancel(
        &self,
        _net: &NetworkParams,
        _args: &ContractArgs,
        _book: &OptionsBook,
    ) -> QueryResponse;

    fn expiry(
        &self,
        _net: &NetworkParams,
        _args: &ContractArgs,
        _book: &OptionsBook,
    ) -> QueryResponse;

    fn settle(
        &self,
        _net: &NetworkParams,
        _args: &ContractArgs,
        _book: &OptionsBook,
    ) -> QueryResponse;

    fn liquidity(&self, _desc: &TrDesc) -> u64;

    fn validate(&self, contract: &OptionsContract) -> bool;
}

impl OptionOps for Client {
    fn initialize(
        &self,
        net: &NetworkParams,
        args: &InitArgs,
        book: &mut OptionsBook,
    ) -> QueryResponse {
        let value = self.call_rpc("listunspent", &[]);
        let mut pset = Pset::new_v2();
        let mut in_total = 0;
        for v in value.as_array().unwrap() {
            if v["asset"].as_str().unwrap() != net.btc_asset().to_string() {
                // Only look for utxos of a bitcoin asset
                continue;
            }
            let inp = pset::Input::from_prevout(OutPoint::new(
                Txid::from_str(&v["txid"].as_str().unwrap()).unwrap(),
                v["vout"].as_u64().unwrap() as u32,
            ));
            let v = bitcoin::Amount::from_float_in(
                v["amount"].as_f64().unwrap(),
                bitcoin::Denomination::Bitcoin,
            )
            .unwrap()
            .to_sat();
            in_total += v;
            pset.add_input(inp);
            if pset.inputs().len() == 2 {
                break;
            }
        }
        if pset.inputs().len() != 2 {
            panic!("Cannot fund pset with two seperate utxos: Wallet must have atleast two utxos")
        }
        let fees = 1_000; // random fixed value for fees.

        if in_total - fees <= 0 {
            panic!("InSufficient funds to pay fees")
        }

        let btc_fees_txout = TxOut::new_fee(fees, net.btc_asset());
        let addr = RpcCall::get_new_address(self);
        let mut dest_txout = pset::Output::new_explicit(
            addr.script_pubkey(),
            in_total - fees,
            net.btc_asset(),
            None,
        );
        dest_txout.blinding_key = addr.blinding_pubkey.map(bitcoin::PublicKey::new);
        dest_txout.blinder_index = Some(0);

        pset.add_output(dest_txout);
        pset.add_output(pset::Output::from_txout(btc_fees_txout));

        let mut pset = self.utxo_update_psbt(&pset);

        let params = BaseParams {
            contract_size: args.contract_size,
            expiry: args.expiry,
            start: args.start,
            strike_price: args.strike_price,
            coll_asset: args.coll_asset,
            settle_asset: args.settle_asset,
        };

        let contract = pset
            .issue_rts(SECP256K1, &mut thread_rng(), params)
            .unwrap();
        let pset = self.wallet_process_psbt(&pset, true);

        let issue_tx = self.finalize_psbt(&pset);
        book.insert(&contract);
        let issue_txid = self.send_raw_transaction(&issue_tx);
        println!("Contract Id: {}", contract.id());
        println!("Issue txid: {}", issue_txid);
        QueryResponse {
            contract_id: contract.id(),
            txid: issue_txid,
        }
    }

    fn fund(&self, net: &NetworkParams, args: &ContractArgs, book: &OptionsBook) -> QueryResponse {
        // Get the contract from the book
        let contract = book
            .get(&args.contract_id)
            .expect("Contract not found in book");
        let desc = contract.funding_desc(SECP256K1);
        let spk = desc.script_pubkey();

        let mut utxos = self.scan_txout_set(&spk);
        // Check which utxo is crt and which is ort
        // The utxo with the lowest vout is the crt
        if utxos.len() != 2 || utxos[0].0.txid != utxos[1].0.txid {
            panic!("Must have exactly two RT UTXOs within the same tx")
        }
        if utxos[0].0.vout > utxos[1].0.vout {
            utxos.swap(0, 1);
        }

        let ort_prevout = utxos.pop().unwrap();
        let crt_prevout = utxos.pop().unwrap();
        let fund_args = FundingParams {
            crt_prevout,
            ort_prevout,
            num_contracts: args.num_contracts,
            crt_dest_addr: self.get_new_address(),
            ort_dest_addr: self.get_new_address(),
        };

        let coll_desc = contract.coll_desc();
        let amt =
            bitcoin::Amount::from_sat(args.num_contracts * contract.params().contract_size as u64);
        let params = &net.addr_params();
        let coll_spk = coll_desc.script_pubkey();
        let addr = elements::Address::from_script(&coll_spk, None, params).unwrap();
        let outputs = vec![(addr, contract.params().coll_asset, amt)];
        let mut pset = self.wallet_create_funded_pset(&outputs);
        pset_fix_output_pos(&mut pset, 0, contract.params().coll_asset, &coll_spk);

        pset.fund_contract(SECP256K1, &mut thread_rng(), contract, &fund_args)
            .unwrap();

        let pset = self.wallet_process_psbt(&pset, true);

        let fund_tx = self.finalize_psbt(&pset);
        let fund_txid = self.send_raw_transaction(&fund_tx);
        println!("Contract Id: {}", contract.id());
        println!("Funding txid: {}", fund_txid);
        QueryResponse {
            contract_id: contract.id(),
            txid: fund_txid,
        }
    }

    fn exercise(
        &self,
        net: &NetworkParams,
        args: &ContractArgs,
        book: &OptionsBook,
    ) -> QueryResponse {
        let contract = book
            .get(&args.contract_id)
            .expect("Contract not found in book");
        let desc = contract.coll_desc();
        let spk = desc.script_pubkey();
        let utxos = self.scan_txout_set(&spk);
        if utxos.is_empty() {
            panic!("No funded UTXOs found for contract")
        }

        // Create the exercise tx
        // Use dummy addresses for op_return as it has no address
        // The op_return is later replaced by the exercise contract API
        let settle_amt =
            bitcoin::Amount::from_sat(args.num_contracts * contract.params().strike_price);
        let params = &net.addr_params();
        let addr = elements::Address::from_script(&spk, None, params).unwrap();
        let dummy_addr = self.get_new_address();
        let dummy_spk = dummy_addr.script_pubkey();
        let outputs = vec![
            (
                dummy_addr,
                contract.ort(),
                bitcoin::Amount::from_sat(args.num_contracts),
            ),
            (addr, contract.params().settle_asset, settle_amt),
        ];

        let mut i = 0;
        let mut retry_count = 0;
        let mut utxo = utxos[i].clone();
        let txid = loop {
            let mut pset = self.wallet_create_funded_pset(&outputs);
            pset_fix_output_pos(&mut pset, 0, contract.ort(), &dummy_spk);
            pset_fix_output_pos(&mut pset, 1, contract.params().settle_asset, &spk);

            let user_params = CovUserParams {
                cov_prevout: utxo, // Use the first utxo for now. We can later on deal with multiple utxos
                num_contracts: args.num_contracts,
                dest_addr: self.get_new_address(),
            };
            pset.exercise_contract(SECP256K1, contract, &user_params)
                .unwrap();

            let pset = self.wallet_process_psbt(&pset, true);
            let fund_tx = self.finalize_psbt(&pset);
            let res = self.send_raw_transaction_faillible(&fund_tx);

            let conf_txid = match res {
                Ok(txid) => break txid,
                Err(conf_txid) => conf_txid,
            };
            let conf_tx = self.get_raw_transaction(conf_txid);
            utxo = match get_utxo(&conf_tx, &spk) {
                Some(utxo) => utxo,
                None => {
                    i += 1;
                    if i >= utxos.len() {
                        panic!("No more contracts on blockchain to interact");
                    }
                    utxos[i].clone()
                }
            };
            retry_count += 1;
            if retry_count > 10 {
                panic!("Cancel failed after 10 tries")
            }
        };
        println!("Contract Id: {}", contract.id());
        println!("Exercise txid: {}", txid);
        QueryResponse {
            contract_id: contract.id(),
            txid: txid,
        }
    }

    fn cancel(
        &self,
        _net: &NetworkParams,
        args: &ContractArgs,
        book: &OptionsBook,
    ) -> QueryResponse {
        let contract = book
            .get(&args.contract_id)
            .expect("Contract not found in book");
        let desc = contract.coll_desc();
        let spk = desc.script_pubkey();
        let utxos = self.scan_txout_set(&spk);
        let txid = retry_tx(self, &utxos, &spk, args, contract, &_cancel);
        println!("Contract Id: {}", contract.id());
        println!("Cancel txid: {}", txid);
        QueryResponse {
            contract_id: contract.id(),
            txid: txid,
        }
    }

    fn expiry(
        &self,
        _net: &NetworkParams,
        args: &ContractArgs,
        book: &OptionsBook,
    ) -> QueryResponse {
        let contract = book
            .get(&args.contract_id)
            .expect("Contract not found in book");
        let desc = contract.coll_desc();
        let spk = desc.script_pubkey();
        let utxos = self.scan_txout_set(&spk);
        let txid = retry_tx(self, &utxos, &spk, args, contract, &_expiry);

        println!("Contract Id: {}", contract.id());
        println!("Expiry txid: {}", txid);
        QueryResponse {
            contract_id: contract.id(),
            txid: txid,
        }
    }

    fn settle(
        &self,
        _net: &NetworkParams,
        args: &ContractArgs,
        book: &OptionsBook,
    ) -> QueryResponse {
        let contract = book
            .get(&args.contract_id)
            .expect("Contract not found in book");
        let desc = contract.settle_desc();
        let spk = desc.script_pubkey();
        let utxos = self.scan_txout_set(&spk);
        let txid = retry_tx(self, &utxos, &spk, args, contract, &_settle);
        println!("Contract Id: {}", contract.id());
        println!("Settle txid: {}", txid);
        QueryResponse {
            contract_id: contract.id(),
            txid: txid,
        }
    }

    fn liquidity(&self, desc: &TrDesc) -> u64 {
        let utxos = self.scan_txout_set(&desc.script_pubkey());
        // Calculate the total amount of collateral
        utxos.iter().map(|u| u.1.value.explicit().unwrap()).sum()
    }

    fn validate(&self, contract: &OptionsContract) -> bool {
        // Check crt_rt and ort_rt outpoints number of confirmations
        let crt_rt_prevout = contract.crt_rt_prevout();
        let ort_rt_prevout = contract.ort_rt_prevout();
        let crt_conf = self.get_num_confirmations(crt_rt_prevout.txid);
        if crt_rt_prevout.txid != ort_rt_prevout.txid
            || crt_rt_prevout.vout != 0
            || ort_rt_prevout.vout != 1
            || crt_conf < 1
        {
            return false;
        }
        let fund_spk = contract.funding_desc(SECP256K1).script_pubkey();
        let init_tx = self.get_raw_transaction(crt_rt_prevout.txid);
        if init_tx.output.len() < 2 {
            return false;
        }
        init_tx.output[0].script_pubkey == fund_spk && init_tx.output[1].script_pubkey == fund_spk
        // The assets and rt blinding cycle are correctly checked by the covenant.
    }
}

fn retry_tx(
    cli: &Client,
    utxos: &[(OutPoint, TxOut)],
    spk: &Script,
    args: &ContractArgs,
    contract: OptionsContract,
    act_fn: &dyn Fn(
        &Client,
        &ContractArgs,
        OptionsContract,
        (OutPoint, TxOut),
    ) -> Result<Txid, Txid>,
) -> Txid {
    if utxos.is_empty() {
        panic!("No UTXOs found for claiming settlement asset")
    }
    let mut i = 0;
    let mut utxo = utxos[i].clone();
    let mut retry_count = 0;
    let txid = loop {
        let res = act_fn(cli, args, contract, utxo);
        let conf_txid = match res {
            Ok(txid) => break txid,
            Err(conf_txid) => conf_txid,
        };
        let conf_tx = cli.get_raw_transaction(conf_txid);
        utxo = match get_utxo(&conf_tx, &spk) {
            Some(utxo) => utxo,
            None => {
                i += 1;
                if i >= utxos.len() {
                    panic!("No more contracts on blockchain to interact");
                }
                utxos[i].clone()
            }
        };
        retry_count += 1;
        if retry_count > 10 {
            panic!("Cancel failed after 10 tries")
        }
    };
    txid
}

fn _cancel(
    cli: &Client,
    args: &ContractArgs,
    contract: OptionsContract,
    utxo: (OutPoint, TxOut),
) -> Result<Txid, Txid> {
    let (dummy_addr1, dummy_addr2) = (cli.get_new_address(), cli.get_new_address());
    let outputs = vec![
        (
            dummy_addr1.clone(),
            contract.crt(),
            bitcoin::Amount::from_sat(args.num_contracts),
        ),
        (
            dummy_addr2.clone(),
            contract.ort(),
            bitcoin::Amount::from_sat(args.num_contracts),
        ),
    ];
    let mut pset = cli.wallet_create_funded_pset(&outputs);
    pset_fix_output_pos(&mut pset, 0, contract.crt(), &dummy_addr1.script_pubkey());
    pset_fix_output_pos(&mut pset, 1, contract.ort(), &dummy_addr2.script_pubkey());

    let user_params = CovUserParams {
        cov_prevout: utxo, // Use the first utxo for now. We can later on deal with multiple utxos
        num_contracts: args.num_contracts,
        dest_addr: cli.get_new_address(),
    };
    pset.cancel_contract(SECP256K1, contract, &user_params)
        .unwrap();

    let pset = cli.wallet_process_psbt(&pset, true);
    let cancel_tx = cli.finalize_psbt(&pset);
    cli.send_raw_transaction_faillible(&cancel_tx)
}

fn _settle(
    cli: &Client,
    args: &ContractArgs,
    contract: OptionsContract,
    utxo: (OutPoint, TxOut),
) -> Result<Txid, Txid> {
    // Create the expiry tx
    // Use dummy addresses for op_return as it has no address
    let dummy_addr1 = cli.get_new_address();
    let outputs = vec![(
        dummy_addr1.clone(),
        contract.crt(),
        bitcoin::Amount::from_sat(args.num_contracts),
    )];
    let mut pset = cli.wallet_create_funded_pset(&outputs);
    pset_fix_output_pos(&mut pset, 0, contract.crt(), &dummy_addr1.script_pubkey());

    let user_params = CovUserParams {
        cov_prevout: utxo,
        num_contracts: args.num_contracts,
        dest_addr: cli.get_new_address(),
    };

    pset.settle_contract(SECP256K1, contract, &user_params)
        .unwrap();
    let pset = cli.wallet_process_psbt(&pset, true);
    let settle_tx = cli.finalize_psbt(&pset);
    cli.send_raw_transaction_faillible(&settle_tx)
}

fn _expiry(
    cli: &Client,
    args: &ContractArgs,
    contract: OptionsContract,
    utxo: (OutPoint, TxOut),
) -> Result<Txid, Txid> {
    // Create the expiry tx
    // Use dummy addresses for op_return as it has no address
    let dummy_addr1 = cli.get_new_address();
    let outputs = vec![(
        dummy_addr1.clone(),
        contract.crt(),
        bitcoin::Amount::from_sat(args.num_contracts),
    )];
    let mut pset = cli.wallet_create_funded_pset(&outputs);
    pset_fix_output_pos(&mut pset, 0, contract.crt(), &dummy_addr1.script_pubkey());

    let user_params = CovUserParams {
        cov_prevout: utxo,
        num_contracts: args.num_contracts,
        dest_addr: cli.get_new_address(),
    };
    pset.expiry_contract(SECP256K1, contract, &user_params)
        .unwrap();

    let pset = cli.wallet_process_psbt(&pset, true);
    let expiry_tx = cli.finalize_psbt(&pset);
    cli.send_raw_transaction_faillible(&expiry_tx)
}

// Obtain the (outpoint, txout) from the transaction and spk
fn get_utxo(tx: &Transaction, spk: &Script) -> Option<(OutPoint, TxOut)> {
    let txid = tx.txid();
    let vout = tx.output.iter().position(|o| o.script_pubkey == *spk)?;
    let outpoint = OutPoint::new(txid, vout as u32);
    let txout = tx.output[vout].clone();
    Some((outpoint, txout))
}

pub(crate) trait RpcCall {
    fn call_rpc(&self, cmd: &str, args: &[Value]) -> Value;
    fn call_rpc_fallible(&self, cmd: &str, args: &[Value]) -> Result<Value, RpcError>;
    fn get_new_address(&self) -> elements::Address;
    fn send_to_address(&self, addr: &elements::Address, amt: bitcoin::Amount) -> elements::Txid;
    fn get_transaction(&self, txid: elements::Txid) -> elements::Transaction;
    fn get_raw_transaction(&self, txid: elements::Txid) -> elements::Transaction;
    fn test_mempool_accept(&self, hex: &elements::Transaction) -> bool;
    fn send_raw_transaction(&self, hex: &elements::Transaction) -> elements::Txid;
    fn send_raw_transaction_faillible(
        &self,
        tx: &elements::Transaction,
    ) -> Result<elements::Txid, elements::Txid>;
    fn generate(&self, blocks: u32);
    fn wallet_process_psbt(&self, pset: &Pset, sign: bool) -> Pset;
    fn issue_asset(
        &self,
        asset_amt: bitcoin::Amount,
        token_amt: bitcoin::Amount,
        blind: bool,
    ) -> (AssetId, AssetId);
    fn utxo_update_psbt(&self, pset: &Pset) -> Pset;
    fn finalize_psbt(&self, psbt: &Pset) -> Transaction;
    fn get_num_confirmations(&self, txid: elements::Txid) -> u64;
    fn scan_txout_set(
        &self,
        raw_spk: &elements::Script,
    ) -> Vec<(elements::OutPoint, elements::TxOut)>;
    fn wallet_create_funded_pset(
        &self,
        outputs: &[(elements::Address, elements::AssetId, bitcoin::Amount)],
    ) -> Pset;
}

impl RpcCall for Client {
    fn call_rpc(&self, cmd: &str, args: &[Value]) -> Value {
        elementsd::bitcoincore_rpc::RpcApi::call::<Value>(self, cmd, args).unwrap()
    }

    fn call_rpc_fallible(&self, cmd: &str, args: &[Value]) -> Result<Value, RpcError> {
        let res = elementsd::bitcoincore_rpc::RpcApi::call::<Value>(self, cmd, args);
        match res {
            Ok(v) => Ok(v),
            Err(elementsd::bitcoincore_rpc::Error::JsonRpc(e)) => {
                if let elementsd::bitcoincore_rpc::jsonrpc::Error::Rpc(e) = e {
                    Err(e)
                } else {
                    panic!("Unexpected error type")
                }
            }
            _ => unreachable!(),
        }
    }

    fn get_new_address(&self) -> elements::Address {
        let addr_str = self
            .call_rpc("getnewaddress", &[])
            .as_str()
            .unwrap()
            .to_string();

        elements::Address::from_str(&addr_str).unwrap()
    }

    fn get_transaction(&self, txid: elements::Txid) -> elements::Transaction {
        let tx_hex = self.call_rpc("gettransaction", &[txid.to_string().into()])["hex"]
            .as_str()
            .unwrap()
            .to_string();

        let tx_bytes = Vec::<u8>::from_hex(&tx_hex).unwrap();
        deserialize(&tx_bytes).unwrap()
    }

    fn get_num_confirmations(&self, txid: elements::Txid) -> u64 {
        self.call_rpc("gettransaction", &[txid.to_string().into()])["confirmations"]
            .as_u64()
            .unwrap()
    }

    fn get_raw_transaction(&self, txid: elements::Txid) -> elements::Transaction {
        let tx_hex = self
            .call_rpc("getrawtransaction", &[txid.to_string().into()])
            .as_str()
            .unwrap()
            .to_string();

        let tx_bytes = Vec::<u8>::from_hex(&tx_hex).unwrap();
        deserialize(&tx_bytes).unwrap()
    }

    fn send_to_address(&self, addr: &elements::Address, amt: bitcoin::Amount) -> elements::Txid {
        let amt = amt.to_btc().to_string();
        let tx_id = self
            .call_rpc("sendtoaddress", &[addr.to_string().into(), amt.into()])
            .as_str()
            .unwrap()
            .to_string();
        elements::Txid::from_str(&tx_id).unwrap()
    }

    fn send_raw_transaction(&self, tx: &elements::Transaction) -> elements::Txid {
        let tx_id = self
            .call_rpc("sendrawtransaction", &[serialize_hex(tx).into()])
            .as_str()
            .unwrap()
            .to_string();

        elements::Txid::from_str(&tx_id).unwrap()
    }

    fn send_raw_transaction_faillible(
        &self,
        tx: &elements::Transaction,
    ) -> Result<elements::Txid, elements::Txid> {
        let res = self.call_rpc_fallible("sendrawtransaction", &[serialize_hex(tx).into()]);
        match res {
            Ok(txid) => Ok(elements::Txid::from_str(&txid.as_str().unwrap()).unwrap()),
            Err(e) => {
                if e.code == -26 {
                    // Transaction already in block chain
                    let txid = e.message.split_whitespace().last().unwrap();
                    Err(elements::Txid::from_str(&txid).unwrap())
                } else {
                    panic!("Unexpected error: {}", e.message)
                }
            }
        }
    }

    fn generate(&self, blocks: u32) {
        let address = RpcCall::get_new_address(self);
        let _value = self.call_rpc(
            "generatetoaddress",
            &[blocks.into(), address.to_string().into()],
        );
    }

    fn test_mempool_accept(&self, tx: &elements::Transaction) -> bool {
        let result = self.call_rpc("testmempoolaccept", &[json!([serialize_hex(tx)])]);
        let allowed = result.get(0).unwrap().get("allowed");
        allowed.unwrap().as_bool().unwrap()
    }

    fn utxo_update_psbt(&self, pset: &Pset) -> Pset {
        let base64 = base64::encode(&serialize(pset));
        let value = self.call_rpc("utxoupdatepsbt", &[base64.into()]);
        psbt_from_base64(value.as_str().unwrap())
    }

    fn wallet_process_psbt(&self, pset: &Pset, sign: bool) -> Pset {
        let base64 = base64::encode(&serialize(pset));
        let value = self.call_rpc("walletprocesspsbt", &[base64.into(), sign.into()]);
        let ret = value.get("psbt").unwrap().as_str().unwrap();
        psbt_from_base64(ret)
    }

    fn finalize_psbt(&self, pset: &Pset) -> Transaction {
        let base64 = base64::encode(&serialize(pset));
        let value = self.call_rpc("finalizepsbt", &[base64.into()]);
        let ret = value.get("hex").unwrap().as_str().unwrap();
        deserialize(&Vec::<u8>::from_hex(ret).unwrap()).unwrap()
    }

    fn issue_asset(
        &self,
        asset_amt: bitcoin::Amount,
        token_amt: bitcoin::Amount,
        blind: bool,
    ) -> (AssetId, AssetId) {
        let ast = asset_amt.to_string_in(bitcoin::Denomination::Bitcoin);
        let tkn = token_amt.to_string_in(bitcoin::Denomination::Bitcoin);
        let ret = self.call_rpc("issueasset", &[ast.into(), tkn.into(), blind.into()]);

        let asset_id = AssetId::from_hex(ret["asset"].as_str().unwrap()).unwrap();
        let token_id = AssetId::from_hex(ret["token"].as_str().unwrap()).unwrap();
        (asset_id, token_id)
    }

    fn scan_txout_set(
        &self,
        raw_spk: &elements::Script,
    ) -> Vec<(elements::OutPoint, elements::TxOut)> {
        let raw_desc = format!("raw({})", raw_spk.to_hex());
        let raw_desc_arr = serde_json::to_value(&[raw_desc]).unwrap();
        let utxos =
            &self.call_rpc("scantxoutset", &["start".into(), raw_desc_arr.into()])["unspents"];
        let mut ret = vec![];
        for utxo_info in utxos.as_array().unwrap() {
            let asset = if let Some(value) = utxo_info.get("asset") {
                confidential::Asset::Explicit(AssetId::from_hex(value.as_str().unwrap()).unwrap())
            } else if let Some(value) = utxo_info.get("assetcommitment") {
                deserialize(&Vec::<u8>::from_hex(value.as_str().unwrap()).unwrap()).unwrap()
            } else {
                panic!("No asset found");
            };
            let amount = if let Some(value) = utxo_info.get("amount") {
                let v = bitcoin::Amount::from_float_in(
                    value.as_f64().unwrap(),
                    bitcoin::Denomination::Bitcoin,
                )
                .unwrap()
                .to_sat();
                confidential::Value::Explicit(v)
            } else if let Some(value) = utxo_info.get("amountcommitment") {
                deserialize(&Vec::<u8>::from_hex(value.as_str().unwrap()).unwrap()).unwrap()
            } else {
                panic!("No amount found");
            };
            let tx_out = elements::TxOut {
                value: amount,
                asset: asset,
                nonce: confidential::Nonce::Null, // We don't care of the nonce
                script_pubkey: elements::Script::from_hex(
                    utxo_info["scriptPubKey"].as_str().unwrap(),
                )
                .unwrap(),
                witness: TxOutWitness::default(),
            };
            let outpoint = OutPoint::new(
                Txid::from_str(&utxo_info["txid"].as_str().unwrap()).unwrap(),
                utxo_info["vout"].as_u64().unwrap() as u32,
            );
            ret.push((outpoint, tx_out));
        }
        ret
    }

    fn wallet_create_funded_pset(
        &self,
        outputs: &[(elements::Address, elements::AssetId, bitcoin::Amount)],
    ) -> Pset {
        let mut out_arr = vec![];
        for (addr, asset, amount) in outputs {
            let addr_str = addr.to_string();
            let asset_str = asset.to_hex();
            let amount_str = amount.to_string_in(bitcoin::Denomination::Bitcoin);
            let obj = json!({
                addr_str: amount_str,
                "asset": asset_str,
            });
            out_arr.push(obj);
        }
        let value = self.call_rpc(
            "walletcreatefundedpsbt",
            &[
                json!([]),
                out_arr.into(),
                0.into(),
                json!({"fee_rate": "1.0", "include_unsafe": true}),
            ],
        );
        let pset_base64 = value["psbt"].as_str().unwrap().to_string();
        deserialize(&base64::decode(&pset_base64).unwrap()).unwrap()
    }
}

fn psbt_from_base64(base64: &str) -> Pset {
    let bytes = base64::decode(&base64).unwrap();
    deserialize(&bytes).unwrap()
}

/// Swap outputs so that the output at target pos is the one with the given asset and spk
fn pset_fix_output_pos(pset: &mut Pset, target_pos: usize, asset: AssetId, spk: &Script) {
    let i = pset
        .outputs()
        .iter()
        .position(|o| o.asset == Some(asset) && &o.script_pubkey == spk);
    pset.outputs_mut()
        .swap(target_pos, i.expect("Must have fund txout"));
}
