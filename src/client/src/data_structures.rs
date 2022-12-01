//! Data structures shared across local client and RPC server

use std::panic;
use std::path::PathBuf;

use bitcoin::hashes::hex::FromHex;
use clap::Args;
use elementsd::bitcoincore_rpc::bitcoin;
use elementsd::bitcoincore_rpc::Client;
use options_lib::BaseParams;
use options_lib::miniscript::elements::{self, AddressParams, AssetId};
use options_lib::OptionsContract;
use secp256k1::hashes::sha256;
use serde::{Deserialize, Serialize};

use crate::contract::OptionsBook;
use crate::rpc::OptionOps;
use crate::utils;

#[derive(Args, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ContractId {
    /// Contract Id
    pub contract_id: sha256::Hash,
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct InitArgs {
    /// The contract size in sats per contract. 1M sat per contract
    #[clap(long)]
    pub contract_size: u64,
    /// The timestamp represented as bitcoin tx `nLockTime`
    #[clap(long)]
    pub expiry: u32,
    /// The start date of the contract as bitcoin tx `nLockTime`
    #[clap(long)]
    pub start: u32,
    /// The strike price in settlement asset per coll asset
    #[clap(short = 'p', long)]
    pub strike_price: u64,
    /// The collateral asset id(reversed as per elements convention)
    #[clap(long)]
    pub coll_asset: AssetId,
    /// The settlement asset id(reversed as per elements convention)
    #[clap(long)]
    pub settle_asset: AssetId,
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct ContractArgs {
    //// The number of contracts to fund/cancel/create/sell
    #[clap(long, short)]
    pub num_contracts: u64,
    /// The id of the contract to fund/cancel/create/sell
    #[clap(long, short)]
    pub contract_id: sha256::Hash,
}

const LIQUID_TLBTC: &'static str =
    "144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49";
const LIQUID_LBTC: &'static str =
    "6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkParams {
    pub network: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryResponse {
    pub contract_id: sha256::Hash,
    pub txid: elements::Txid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfoResponse {
    pub contract_id: sha256::Hash,
    pub coll_asset: AssetId,
    pub settle_asset: AssetId,
    pub contract_size: u64,
    pub strike_price: u64,
    pub expiry: u32,
    pub start: u32,
    pub crt: AssetId,
    pub ort: AssetId,
    pub liquidity: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptionsImportParams {
    pub contract_size: u64,
    pub expiry: u32,
    pub start: u32,
    pub strike_price: u64,
    pub coll_asset: AssetId,
    pub settle_asset: AssetId,
    pub crt_rt_prevout_txid: elements::Txid,
    pub crt_rt_prevout_vout: u32,
    pub ort_rt_prevout_txid: elements::Txid,
    pub ort_rt_prevout_vout: u32,
}

impl OptionsImportParams {

    pub fn from_contract(contract: OptionsContract) -> Self {
        Self {
            contract_size: contract.params().contract_size,
            expiry: contract.params().expiry,
            start: contract.params().start,
            strike_price: contract.params().strike_price,
            coll_asset: contract.params().coll_asset,
            settle_asset: contract.params().settle_asset,
            crt_rt_prevout_txid: contract.crt_rt_prevout().txid,
            crt_rt_prevout_vout: contract.crt_rt_prevout().vout,
            ort_rt_prevout_txid: contract.ort_rt_prevout().txid,
            ort_rt_prevout_vout: contract.ort_rt_prevout().vout,
        }
    }

    pub fn to_contract(&self) -> OptionsContract {
        let params = BaseParams {
            contract_size: self.contract_size,
            expiry: self.expiry,
            start: self.start,
            strike_price: self.strike_price,
            coll_asset: self.coll_asset,
            settle_asset: self.settle_asset,
        };
        let crt_prevout = elements::OutPoint {
            txid: self.crt_rt_prevout_txid,
            vout: self.crt_rt_prevout_vout,
        };
        let ort_prevout = elements::OutPoint {
            txid: self.ort_rt_prevout_txid,
            vout: self.ort_rt_prevout_vout,
        };
        OptionsContract::new(params, crt_prevout, ort_prevout)
    }
}

impl InfoResponse {
    pub fn from_contract(contract: &OptionsContract, e_cli: &Client) -> Self {
        InfoResponse {
            contract_id: contract.id(),
            coll_asset: contract.params().coll_asset,
            settle_asset: contract.params().settle_asset,
            contract_size: contract.params().contract_size,
            strike_price: contract.params().strike_price,
            expiry: contract.params().expiry,
            start: contract.params().start,
            crt: contract.crt(),
            ort: contract.ort(),
            liquidity: e_cli.liquidity(&contract.coll_desc()),
        }
    }
}

impl NetworkParams {
    pub fn btc_asset(&self) -> AssetId {
        if self.network == "liquidtestnet" {
            AssetId::from_hex(LIQUID_TLBTC).unwrap()
        } else if self.network == "liquidv1" {
            AssetId::from_hex(LIQUID_LBTC).unwrap()
        } else if self.network == "elementsregtest" {
            AssetId::from_hex("b2e15d0d7a0c94e4e2ce0fe6e8691b9e451377f6e46e8045a86f7c4b5d4f0f23")
                .unwrap()
        } else if self.network == "liquidregtest" {
            todo!("Fill assetid for here. This is used by integretion tests")
        } else {
            panic!("Unrecognized network")
        }
    }

    pub fn addr_params(&self) -> &'static AddressParams {
        if self.network == "liquidtestnet" {
            &AddressParams::LIQUID_TESTNET
        } else if self.network == "liquidv1" {
            &AddressParams::LIQUID
        } else if self.network == "elementsregtest" {
            &AddressParams::ELEMENTS
        } else if self.network == "liquidregtest" {
            &AddressParams::ELEMENTS
        } else {
            panic!("Unrecognized network")
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientArgs {
    /// Sets a custom config file
    pub data_dir: Option<PathBuf>,
    /// RPC port
    pub rpc_port: u16,
    /// Network
    pub network: String,
    /// Wallet name to use incase there are multiple wallets
    pub wallet_name: Option<String>,
}

impl ClientArgs {
    pub fn liquid_testnet() -> Self {
        Self {
            data_dir: None,
            rpc_port: 18891,
            network: "liquidtestnet".to_string(),
            wallet_name: None,
        }
    }
}

impl ClientArgs {
    /// Read the already opened options
    pub fn read_options_db(&self) -> OptionsBook {
        let data_dir = utils::_data_dir(&self.data_dir);
        let db_path = utils::_options_db_file(data_dir);
        OptionsBook::new(&db_path)
    }

    /// Connect to a local node
    pub fn elements_cli(&self) -> Client {
        let data_dir = utils::_data_dir(&self.data_dir);
        utils::_new_client(data_dir, self.rpc_port, &self.network, &self.wallet_name)
    }
}
