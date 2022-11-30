use std::fmt::Debug;
use std::path::{PathBuf};
use std::{env, panic, process};
use options_rpc::data_structures::InfoResponse;
use options_rpc::{data_structures, utils};

use clap::{Parser, Subcommand};
use data_structures::{InitArgs, ContractArgs, ContractId, NetworkParams};
use elementsd::bitcoincore_rpc::{Client};
use options_lib::OptionsContract;
use options_rpc::rpc::OptionOps;

use options_rpc::contract::OptionsBook;
use serde::Serialize;

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

impl App {
    fn read_options_db(&self) -> OptionsBook {
        let data_dir = utils::_data_dir(&self.data_dir);
        let opt_db_file = utils::_options_db_file(data_dir);
        OptionsBook::new(&opt_db_file)
    }

    fn elements_cli(&self) -> Client {
        let data_dir = utils::_data_dir(&self.data_dir);
        utils::_new_client(data_dir, self.rpc_port, &self.network, &self.wallet_name)
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
    let net = NetworkParams {
        network: clap_cli.network.clone(),
    };

    // You can check for the existence of subcommands, and if found use their
    // matches just as you would the top level cmd
    match &clap_cli.command {
        Some(Commands::Initialize(args)) => print_string(&e_cli.initialize(&net, &args, &mut book)),
        Some(Commands::Fund(args)) => print_string(&e_cli.fund(&net, &args, &book)),
        Some(Commands::Exercise(args)) => print_string(&e_cli.exercise(&net, &args, &book)),
        Some(Commands::Cancel(args)) => print_string(&e_cli.cancel(&net, &args, &book)),
        Some(Commands::Expiry(args)) => print_string(&e_cli.expiry(&net, &args, &book)),
        Some(Commands::Settle(args)) => print_string(&e_cli.settle(&net, &args, &book)),
        Some(Commands::List) => {
            let num_max_entries = 100;
            let mut res = Vec::with_capacity(num_max_entries);
            for item in book.book.iter().take(100) {
                let (_id, contract) = item.unwrap();
                let contract = OptionsContract::from_slice(&contract);
                let info = InfoResponse::from_contract(&contract, &e_cli);
                res.push(info);
            }
            print_string(&res);
        }
        Some(Commands::Info(id)) => match book.get(&id.id) {
            None => panic!("Contract ID not found"),
            Some(x) => {
                let info = InfoResponse::from_contract(&x, &e_cli);
                print_string(&info);
            }
        },
        None => {
            panic!("See --help for usage");
        }
    }

    // Continued program logic goes here...
}

fn print_string<T>(value: &T)
where
    T: ?Sized + Serialize + Debug,
{
    println!("{}", serde_json::to_string_pretty(value).unwrap())
}