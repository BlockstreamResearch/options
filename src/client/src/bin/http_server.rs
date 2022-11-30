use actix_web::web::Data;
use actix_web::{middleware, web, App, HttpResponse, HttpServer};
use options_lib::OptionsContract;
use options_rpc::rpc::OptionOps;
use options_rpc::ClientArgs;

use options_rpc::data_structures::{
    ContractArgs, ContractId, InfoResponse, InitArgs, NetworkParams,
};

async fn info(item: web::Json<ContractId>, args: Data<ClientArgs>) -> HttpResponse {
    let db = args.read_options_db();
    let e_cli = args.elements_cli();
    let contract = db.get(&item.id).unwrap();
    let info = InfoResponse::from_contract(&contract, &e_cli);
    HttpResponse::Ok().json(info) // <- send response
}

async fn list(args: Data<ClientArgs>) -> HttpResponse {
    let num_max_entries = 30;
    let mut res = Vec::with_capacity(num_max_entries);
    let db = args.read_options_db();
    let e_cli = args.elements_cli();
    for item in db.book.iter().take(100) {
        let (_id, contract) = item.unwrap();
        let contract = OptionsContract::from_slice(&contract);
        let info = InfoResponse::from_contract(&contract, &e_cli);
        res.push(info);
    }
    HttpResponse::Ok().json(res) // <- send response
}

async fn init(init_args: web::Json<InitArgs>, data: Data<ClientArgs>) -> HttpResponse {
    let mut db = data.read_options_db();
    let e_cli = data.elements_cli();
    let net = NetworkParams {
        network: data.network.clone(),
    };
    let res = e_cli.initialize(&net, &init_args, &mut db);
    HttpResponse::Ok().json(res) // <- send response
}

async fn fund(fund_args: web::Json<ContractArgs>, data: Data<ClientArgs>) -> HttpResponse {
    let db = data.read_options_db();
    let e_cli = data.elements_cli();
    let net = NetworkParams {
        network: data.network.clone(),
    };
    let res = e_cli.fund(&net, &fund_args, &db);
    HttpResponse::Ok().json(res) // <- send response
}

async fn exercise(exercise_args: web::Json<ContractArgs>, data: Data<ClientArgs>) -> HttpResponse {
    let db = data.read_options_db();
    let e_cli = data.elements_cli();
    let net = NetworkParams {
        network: data.network.clone(),
    };
    let res = e_cli.exercise(&net, &exercise_args, &db);
    HttpResponse::Ok().json(res) // <- send response
}

async fn cancel(cancel_args: web::Json<ContractArgs>, data: Data<ClientArgs>) -> HttpResponse {
    let db = data.read_options_db();
    let e_cli = data.elements_cli();
    let net = NetworkParams {
        network: data.network.clone(),
    };
    let res = e_cli.cancel(&net, &cancel_args, &db);
    HttpResponse::Ok().json(res) // <- send response
}

async fn expiry(expiry_args: web::Json<ContractArgs>, data: Data<ClientArgs>) -> HttpResponse {
    let db = data.read_options_db();
    let e_cli = data.elements_cli();
    let net = NetworkParams {
        network: data.network.clone(),
    };
    let res = e_cli.expiry(&net, &expiry_args, &db);
    HttpResponse::Ok().json(res) // <- send response
}

async fn settle(settle_args: web::Json<ContractArgs>, data: Data<ClientArgs>) -> HttpResponse {
    let db = data.read_options_db();
    let e_cli = data.elements_cli();
    let net = NetworkParams {
        network: data.network.clone(),
    };
    let res = e_cli.settle(&net, &settle_args, &db);
    HttpResponse::Ok().json(res) // <- send response
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    log::info!("starting HTTP server at http://localhost:8080");

    let args = Data::new(ClientArgs::liquid_testnet());

    HttpServer::new(move || {
        App::new()
            // enable logger
            .wrap(middleware::Logger::default())
            .app_data(web::JsonConfig::default().limit(4096)) // <- limit size of the payload (global configuration)
            .app_data(args.clone())
            .service(web::resource("/info").route(web::post().to(info)))
            .service(web::resource("/list").route(web::post().to(list)))
            .service(web::resource("/init").route(web::post().to(init)))
            .service(web::resource("/fund").route(web::post().to(fund)))
            .service(web::resource("/cancel").route(web::post().to(cancel)))
            .service(web::resource("/expiry").route(web::post().to(expiry)))
            .service(web::resource("/exercise").route(web::post().to(exercise)))
            .service(web::resource("/settle").route(web::post().to(settle)))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
