use std::collections::BTreeMap;
use std::fs::File;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::{env, panic, process};

use clap::{Args, Parser, Subcommand};
use elementsd::bitcoincore_rpc::bitcoin::hashes::hex::FromHex;
use elementsd::bitcoincore_rpc::{Auth, Client, RpcApi};
use options_lib::miniscript::elements::{AddressParams, AssetId};
use options_lib::OptionsContract;
use rpc::OptionOps;
use secp256k1::hashes::sha256;

use crate::contract::OptionsBook;
mod contract;
mod rpc;

#[derive(Parser)]
#[clap(name = "Options Client")]
#[clap(author = "Sanket K <sanket1729@blockstream.com>")]
#[clap(version = "0.1")]
#[clap(about = "Interact with call/put options on elements/liquid", long_about = None)]
struct App {
    /// Sets a custom config file
    #[clap(short, long, value_parser, value_name = "FOLDER")]
    data_dir: Option<PathBuf>,
    /// RPC port
    #[clap(short, long, default_value_t = 18891)]
    rpc_port: u16,
    /// Network
    #[clap(short, long, default_value_t = String::from("liquidtestnet"))]
    network: String,
    /// Wallet name to use incase there are multiple wallets
    #[clap(short, long)]
    wallet_name: Option<String>,
    /// Available commands
    #[clap(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize the options contract with parameters
    Initialize(InitArgs),
    /// Fund the options contract
    Fund(ContractArgs),
    /// Exercise the options contract
    Exercise(ContractArgs),
    /// Cancel the options contract
    Cancel(ContractArgs),
    /// Expire the options contract
    Expiry(ContractArgs),
    /// Claim the settlement asset from an exercise options contract
    Settle(ContractArgs),
    /// List all avaiable options contracts
    List,
    /// Obtains information about the given options contract
    Info(ContractId),
}

#[derive(Args, PartialEq, Eq, PartialOrd, Ord)]
pub struct ContractId {
    /// Contract Id
    pub id: sha256::Hash,
}

#[derive(Debug, Clone, Args)]
pub(crate) struct InitArgs {
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

#[derive(Debug, Clone, Args)]
pub(crate) struct ContractArgs {
    //// The number of contracts to fund/cancel/create/sell
    #[clap(long, short)]
    pub num_contracts: u64,
    /// The id of the contract to fund/cancel/create/sell
    #[clap(long, short)]
    pub contract_id: sha256::Hash,
}

/// This file is created at the home directory
const DEFAULT_CFG: &'static str = "liquidtestnet";
const LOCAL_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);

const LIQUID_TLBTC: &'static str =
    "144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49";
const LIQUID_LBTC: &'static str =
    "6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d";

impl App {
    fn btc_asset(&self) -> AssetId {
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

    fn addr_params(&self) -> &'static AddressParams {
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

    fn data_dir(&self) -> PathBuf {
        if let Some(buf) = &self.data_dir {
            buf.clone()
        } else {
            let home_dir =
                env::var("HOME").expect("Should have $HOME defined to create books directory");
            let rel_path = self.data_dir.as_deref().unwrap_or(Path::new(DEFAULT_CFG));
            let mut cfg_path = PathBuf::new();
            cfg_path.push(Path::new(&home_dir));
            cfg_path.push(rel_path);
            cfg_path
        }
    }

    fn options_db_file(&self) -> PathBuf {
        let mut db_path = self.data_dir();
        db_path.push(".options.db");
        db_path
    }

    /// Read the already opened options
    fn read_options_db(&self) -> OptionsBook {
        let opt_db_file = self.options_db_file();
        if !opt_db_file.is_file() {
            let file = File::create(opt_db_file).expect("Cannot create config file");
            let book = OptionsBook::new(BTreeMap::new());
            serde_json::to_writer(&file, &book).expect("Writer error");
            book
        } else {
            // Read the book from config file
            let file = File::open(opt_db_file).expect("Cannot find config file");
            serde_json::from_reader(&file).expect("Corrupted config file")
        }
    }

    /// Connect to a local node
    fn elements_cli(&self) -> Client {
        let cfg_path = self.data_dir();
        let rpc_socket = SocketAddrV4::new(LOCAL_IP, self.rpc_port);
        let cookie_file = cfg_path.join(&self.network).join(".cookie");
        let rpc_url = format!("http://{}", rpc_socket);
        let base_cli = Client::new(&rpc_url, Auth::CookieFile(cookie_file.clone()))
            .expect("Client creation error: You can provide the datadir location using --datadir(default ~/.elements)");

        // Make a wallet client
        let wallets = base_cli.list_wallets().expect("RPC: List Wallets failed");
        let wallet_to_use = match wallets.len() {
            0 => panic!("Atleast one wallet must be loaded"),
            1 => &wallets[0],
            _ => self.wallet_name.as_ref().expect(
                "Multiple loaded wallets found. Specify which wallet to use using wallet_name arg",
            ),
        };
        let node_url_default = format!("{}/wallet/{}", rpc_url, wallet_to_use);
        Client::new(&node_url_default, Auth::CookieFile(cookie_file.clone()))
            .expect("Wallet Client creation error")
    }

    /// Adds a new option to the book and serializes it to the disk.
    pub(crate) fn add_contract(&self, contract: OptionsContract, book: &mut OptionsBook) {
        book.book.insert(contract.id(), contract);
        let file = File::create(self.options_db_file()).expect("Cannot find config file");
        serde_json::to_writer(file, &book).unwrap();
    }
}

fn main() {
    // Apply a custom panic hook to print a more user-friendly message
    // in case the execution fails.
    // We skip this for people that are interested in the panic message.
    if env::var("RUST_BACKTRACE").unwrap_or(String::new()) != "1" {
        panic::set_hook(Box::new(|info| {
            let message = if let Some(m) = info.payload().downcast_ref::<String>() {
                m
            } else if let Some(m) = info.payload().downcast_ref::<&str>() {
                m
            } else {
                "No error message provided"
            };
            eprintln!("Execution failed: {}", message);
            process::exit(1);
        }));
    }

    let clap_cli = App::parse();

    let mut book = clap_cli.read_options_db();
    let e_cli = clap_cli.elements_cli();

    // You can check for the existence of subcommands, and if found use their
    // matches just as you would the top level cmd
    match &clap_cli.command {
        Some(Commands::Initialize(args)) => e_cli.initialize(&clap_cli, &args, &mut book),
        Some(Commands::Fund(args)) => e_cli.fund(&clap_cli, &args, &book),
        Some(Commands::Exercise(args)) => e_cli.exercise(&clap_cli, &args, &book),
        Some(Commands::Cancel(args)) => e_cli.cancel(&clap_cli, &args, &book),
        Some(Commands::Expiry(args)) => e_cli.expiry(&clap_cli, &args, &book),
        Some(Commands::Settle(args)) => e_cli.settle(&clap_cli, &args, &book),
        Some(Commands::List) => {
            for (id, contract) in book.book.iter() {
                println!(
                    "{:<66}: {:<32} {:<32} {:<10} {:<10} {:<10}",
                    "Contract ID",
                    "Collateral Asset(First 16)",
                    "Settlement Asset(First 16)",
                    "Strike",
                    "Expiry",
                    "Liquidity"
                );
                println!(
                    "{:<66}: {:.32} {:.32} {:<10} {:<10} {:<10}",
                    id.to_string(),
                    contract.params().coll_asset.to_string(),
                    contract.params().settle_asset.to_string(),
                    contract.params().strike_price,
                    contract.params().expiry,
                    e_cli.liquidity(&book, &contract.coll_desc())
                );
            }
        }
        Some(Commands::Info(id)) => match book.book.get(&id.id) {
            None => panic!("Contract ID not found"),
            Some(x) => {
                println!("Collateral Asset: {}", x.params().coll_asset.to_string());
                println!("Settlement Asset: {}", x.params().settle_asset.to_string());
                println!("Contract Size: {}", x.params().contract_size);
                println!("Strike Price: {}", x.params().strike_price);
                println!("Expiry: {}", x.params().expiry);
                println!("Start: {}", x.params().start);
                println!("CRT asset: {}", x.crt());
                println!("ORT asset: {}", x.ort());
                println!("CRT-RT asset: {}", x.crt_rt());
                println!("ORT-RT asset: {}", x.ort_rt());
                println!("liquidity: {}", e_cli.liquidity(&book, &x.coll_desc()));
            }
        },
        None => {
            panic!("See --help for usage");
        }
    }

    // Continued program logic goes here...
}
