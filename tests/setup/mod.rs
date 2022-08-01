pub extern crate options;

pub extern crate elements_miniscript as miniscript;
use elementsd::bitcoincore_rpc::jsonrpc::base64;
use miniscript::elements::encode::serialize;
use miniscript::elements::{AssetId, Transaction};
use miniscript::{bitcoin, elements};
use std::str::FromStr;

use elements::encode::{deserialize, serialize_hex};
use elements::hashes::hex::FromHex;
use elements::pset::PartiallySignedTransaction as Psbt;
use elements::BlockHash;
use elementsd::bitcoincore_rpc::jsonrpc::serde_json::{json, Value};
use elementsd::bitcoind::bitcoincore_rpc::RpcApi;
use elementsd::bitcoind::{self, BitcoinD};
use elementsd::ElementsD;

// We are not using pegins right now, but it might be required in case in future
// if we extend the tests to check pegins etc.
pub fn setup(validate_pegin: bool) -> (ElementsD, Option<BitcoinD>, elements::BlockHash, AssetId) {
    let mut bitcoind = None;
    if validate_pegin {
        let bitcoind_exe = bitcoind::exe_path().unwrap();
        let bitcoind_conf = bitcoind::Conf::default();
        bitcoind = Some(bitcoind::BitcoinD::with_conf(&bitcoind_exe, &bitcoind_conf).unwrap());
    }

    let mut conf = elementsd::Conf::new(bitcoind.as_ref());

    // HACK: Upstream has issued only 21 million sats intially, but our hard coded tests
    // consume more coins. In order to avoid further conflicts, mutate the default arg here.

    let arg_pos = conf
        .0
        .args
        .iter()
        .position(|x| x.starts_with("-initialfreecoins="));

    match arg_pos {
        Some(i) => conf.0.args[i] = "-initialfreecoins=210000000000",
        None => conf.0.args.push("-initialfreecoins=210000000000"),
    };

    let elementsd = ElementsD::with_conf(elementsd::exe_path().unwrap(), &conf).unwrap();

    let create = elementsd.call("createwallet", &["wallet".into()]);
    assert_eq!(create.get("name").unwrap(), "wallet");

    let rescan = elementsd.call("rescanblockchain", &[]);
    assert_eq!(rescan.get("stop_height").unwrap().as_u64().unwrap(), 0);

    let balances = elementsd.call("getbalances", &[]);
    let mine = balances.get("mine").unwrap();
    let trusted = mine.get("trusted").unwrap();
    assert_eq!(trusted.get("bitcoin").unwrap().as_f64().unwrap(), 2100.0);

    let v = elementsd.call("listunspent", &[]);
    let btc_asset_id = AssetId::from_hex(&v[0]["asset"].as_str().unwrap()).unwrap();

    let genesis_str = elementsd.call("getblockhash", &[0u32.into()]);
    let genesis_str = genesis_str.as_str().unwrap();
    let genesis_hash = BlockHash::from_str(genesis_str).unwrap();

    (elementsd, bitcoind, genesis_hash, btc_asset_id)
}
// Upstream all common methods later
pub trait Call {
    fn call(&self, cmd: &str, args: &[Value]) -> Value;
    fn get_new_address(&self) -> elements::Address;
    fn send_to_address(&self, addr: &elements::Address, amt: bitcoin::Amount) -> elements::Txid;
    fn get_transaction(&self, txid: &elements::Txid) -> elements::Transaction;
    fn test_mempool_accept(&self, hex: &elements::Transaction) -> bool;
    fn send_raw_transaction(&self, hex: &elements::Transaction) -> elements::Txid;
    fn generate(&self, blocks: u32);
    fn wallet_process_psbt(&self, pset: &Psbt, sign: bool) -> Psbt;
    fn issue_asset(
        &self,
        asset_amt: bitcoin::Amount,
        token_amt: bitcoin::Amount,
        blind: bool,
    ) -> (AssetId, AssetId);
    fn utxo_update_psbt(&self, pset: &Psbt) -> Psbt;
    fn finalize_psbt(&self, psbt: &Psbt) -> Transaction;
}

impl Call for ElementsD {
    fn call(&self, cmd: &str, args: &[Value]) -> Value {
        self.client().call::<Value>(cmd, args).unwrap()
    }

    fn get_new_address(&self) -> elements::Address {
        let addr_str = self
            .call("getnewaddress", &[])
            .as_str()
            .unwrap()
            .to_string();

        elements::Address::from_str(&addr_str).unwrap()
    }

    fn get_transaction(&self, txid: &elements::Txid) -> elements::Transaction {
        let tx_hex = self.call("gettransaction", &[txid.to_string().into()])["hex"]
            .as_str()
            .unwrap()
            .to_string();

        let tx_bytes = Vec::<u8>::from_hex(&tx_hex).unwrap();
        deserialize(&tx_bytes).unwrap()
    }

    fn send_to_address(&self, addr: &elements::Address, amt: bitcoin::Amount) -> elements::Txid {
        let amt = amt.as_btc().to_string();
        let tx_id = self
            .call("sendtoaddress", &[addr.to_string().into(), amt.into()])
            .as_str()
            .unwrap()
            .to_string();
        elements::Txid::from_str(&tx_id).unwrap()
    }

    fn send_raw_transaction(&self, tx: &elements::Transaction) -> elements::Txid {
        let tx_id = self
            .call("sendrawtransaction", &[serialize_hex(tx).into()])
            .as_str()
            .unwrap()
            .to_string();

        elements::Txid::from_str(&tx_id).unwrap()
    }

    fn generate(&self, blocks: u32) {
        let address = self.get_new_address();
        let _value = self.call(
            "generatetoaddress",
            &[blocks.into(), address.to_string().into()],
        );
    }

    fn test_mempool_accept(&self, tx: &elements::Transaction) -> bool {
        let result = self.call("testmempoolaccept", &[json!([serialize_hex(tx)])]);
        let allowed = result.get(0).unwrap().get("allowed");
        allowed.unwrap().as_bool().unwrap()
    }

    fn utxo_update_psbt(&self, pset: &Psbt) -> Psbt {
        let base64 = base64::encode(&serialize(pset));
        let value = self.call("utxoupdatepsbt", &[base64.into()]);
        psbt_from_base64(value.as_str().unwrap())
    }

    fn wallet_process_psbt(&self, pset: &Psbt, sign: bool) -> Psbt {
        let base64 = base64::encode(&serialize(pset));
        let value = self.call("walletprocesspsbt", &[base64.into(), sign.into()]);
        let ret = value.get("psbt").unwrap().as_str().unwrap();
        psbt_from_base64(ret)
    }

    fn finalize_psbt(&self, pset: &Psbt) -> Transaction {
        let base64 = base64::encode(&serialize(pset));
        let value = self.call("finalizepsbt", &[base64.into()]);
        let ret = value.get("hex").unwrap().as_str().unwrap();
        println!("{}", ret);
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
        let ret = self.call("issueasset", &[ast.into(), tkn.into(), blind.into()]);

        let asset_id = AssetId::from_hex(ret["asset"].as_str().unwrap()).unwrap();
        let token_id = AssetId::from_hex(ret["token"].as_str().unwrap()).unwrap();
        (asset_id, token_id)
    }
}

fn psbt_from_base64(base64: &str) -> Psbt {
    let bytes = base64::decode(&base64).unwrap();
    deserialize(&bytes).unwrap()
}
