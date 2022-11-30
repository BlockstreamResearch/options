///! Data structures shared across local client and RPC server
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::{env, panic};

use elementsd::bitcoincore_rpc::{Auth, Client, RpcApi};

/// This file is created at the home directory
const DEFAULT_CFG: &'static str = "liquidtestnet";
const LOCAL_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);

pub fn _data_dir(path: &Option<PathBuf>) -> PathBuf {
    if let Some(buf) = path {
        buf.clone()
    } else {
        let home_dir =
            env::var("HOME").expect("Should have $HOME defined to create books directory");
        let rel_path = path.as_deref().unwrap_or(Path::new(DEFAULT_CFG));
        let mut cfg_path = PathBuf::new();
        cfg_path.push(Path::new(&home_dir));
        cfg_path.push(rel_path);
        cfg_path
    }
}

pub fn _options_db_file(mut db_path: PathBuf) -> PathBuf {
    db_path.push("options.db");
    db_path
}

pub fn _new_client(
    data_dir: PathBuf,
    rpc_port: u16,
    network: &str,
    wallet_name: &Option<String>,
) -> Client {
    let cfg_path = data_dir;
    let rpc_socket = SocketAddrV4::new(LOCAL_IP, rpc_port);
    let cookie_file = cfg_path.join(&network).join(".cookie");
    let rpc_url = format!("http://{}", rpc_socket);
    let base_cli = Client::new(&rpc_url, Auth::CookieFile(cookie_file.clone()))
        .expect("Client creation error: You can provide the datadir location using --datadir(default ~/.elements)");

    // Make a wallet client
    let wallets = base_cli.list_wallets().expect("RPC: List Wallets failed");
    let wallet_to_use = match wallets.len() {
        0 => panic!("Atleast one wallet must be loaded"),
        1 => &wallets[0],
        _ => wallet_name.as_ref().expect(
            "Multiple loaded wallets found. Specify which wallet to use using wallet_name arg",
        ),
    };
    let node_url_default = format!("{}/wallet/{}", rpc_url, wallet_to_use);
    Client::new(&node_url_default, Auth::CookieFile(cookie_file.clone()))
        .expect("Wallet Client creation error")
}
