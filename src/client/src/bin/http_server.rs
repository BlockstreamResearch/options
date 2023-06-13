use actix_web::web::Data;
use actix_web::{middleware, web, App, HttpResponse, HttpServer};
use options_lib::OptionsContract;
use options_rpc::rpc::OptionOps;
use options_rpc::ClientArgs;

use options_rpc::data_structures::{
    ContractArgs, ContractId, InfoResponse, InitArgs, NetworkParams, OptionsImportParams,
};

async fn info(item: web::Json<ContractId>, args: Data<ClientArgs>) -> HttpResponse {
    let db = args.read_options_db();
    let e_cli = args.elements_cli();
    let contract = db.get(&item.contract_id).unwrap();
    let info = InfoResponse::from_contract(&contract, &e_cli);
    HttpResponse::Ok().json(info) // <- send response
}

async fn list(args: Data<ClientArgs>) -> HttpResponse {
    let num_max_entries = 1000;
    let mut res = Vec::with_capacity(num_max_entries);
    let db = args.read_options_db();
    let e_cli = args.elements_cli();
    for item in db.book.iter().take(num_max_entries) {
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

async fn import(
    import_args: web::Json<OptionsImportParams>,
    data: Data<ClientArgs>,
) -> HttpResponse {
    let db = data.read_options_db();
    let contract = import_args.to_contract();
    let e_cli = data.elements_cli();
    if !e_cli.validate(&contract) {
        return HttpResponse::BadRequest().into();
    }
    db.insert(&contract);
    let res = ContractId {
        contract_id: contract.id(),
    };
    HttpResponse::Ok().json(res) // <- send response
}

async fn export(export_args: web::Json<ContractId>, data: Data<ClientArgs>) -> HttpResponse {
    let db = data.read_options_db();
    let contract = db.get(&export_args.contract_id).unwrap();
    let res = OptionsImportParams::from_contract(contract);
    HttpResponse::Ok().json(res) // <- send response
}

async fn remove(remove_args: web::Json<ContractId>, data: Data<ClientArgs>) -> HttpResponse {
    let db = data.read_options_db();
    db.remove(&remove_args.contract_id);
    HttpResponse::Ok().json(true) // <- send response
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
            .service(web::resource("/expire").route(web::post().to(expiry)))
            .service(web::resource("/expiry").route(web::post().to(expiry)))
            .service(web::resource("/exercise").route(web::post().to(exercise)))
            .service(web::resource("/settle").route(web::post().to(settle)))
            .service(web::resource("/import").route(web::post().to(import)))
            .service(web::resource("/export").route(web::post().to(export)))
            .service(web::resource("/remove").route(web::post().to(remove)))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
