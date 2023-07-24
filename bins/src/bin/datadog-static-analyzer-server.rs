use getopts::Options;
use kernel::constants::VERSION;
use rocket::fairing::{Fairing, Info, Kind};
use rocket::fs::NamedFile;
use rocket::http::Header;
use rocket::serde::json::{json, Json, Value};
use rocket::{Request as RocketRequest, Response, State};
use server::model::analysis_request::AnalysisRequest;
use server::model::tree_sitter_tree_request::TreeSitterRequest;
use server::request::process_analysis_request;
use server::tree_sitter_tree::process_tree_sitter_tree_request;
use std::env;
use std::path::Path;
use std::process::exit;

pub struct CORS;

// Adding CORS for the server.
// See https://stackoverflow.com/questions/62412361/how-to-set-up-cors-or-options-for-rocket-rs
// for more information.
#[rocket::async_trait]
impl Fairing for CORS {
    fn info(&self) -> Info {
        Info {
            name: "Add CORS headers to responses",
            kind: Kind::Response,
        }
    }

    async fn on_response<'r>(&self, _request: &'r RocketRequest<'_>, response: &mut Response<'r>) {
        response.set_header(Header::new("Access-Control-Allow-Origin", "*"));
        response.set_header(Header::new(
            "Access-Control-Allow-Methods",
            "POST, GET, PATCH, OPTIONS",
        ));
        response.set_header(Header::new("Access-Control-Allow-Headers", "*"));
        response.set_header(Header::new("Access-Control-Allow-Credentials", "true"));
    }
}

#[rocket::get("/languages", format = "application/json")]
fn languages() -> Value {
    let languages: Vec<String> = kernel::model::common::ALL_LANGUAGES
        .iter()
        .map(|x| format!("{}", x))
        .collect();
    json!(languages)
}

#[rocket::post("/analyze", format = "application/json", data = "<request>")]
fn analyze(request: Json<AnalysisRequest>) -> Value {
    json!(process_analysis_request(request.into_inner()))
}

#[rocket::post("/get-treesitter-ast", format = "application/json", data = "<request>")]
fn get_tree(request: Json<TreeSitterRequest>) -> Value {
    json!(process_tree_sitter_tree_request(request.into_inner()))
}

#[rocket::get("/version", format = "text/html")]
fn get_version() -> String {
    VERSION.to_string()
}

#[rocket::get("/static/<name>", format = "text/html")]
async fn serve_static(
    server_configuration: &State<ServerConfiguration>,
    name: &str,
) -> Option<NamedFile> {
    if server_configuration.static_directory.is_none()
        || name.contains("..")
        || name.starts_with('.')
    {
        return None;
    }

    let s = server_configuration.static_directory.as_ref().unwrap();

    let full_path = Path::new(s).join(name);
    NamedFile::open(full_path).await.ok()
}

#[rocket::get("/ping", format = "text/html")]
fn ping() -> String {
    "pong".to_string()
}

/// Catches all OPTION requests in order to get the CORS related Fairing triggered.
#[rocket::options("/<_..>")]
fn get_options() -> String {
    /* Intentionally left empty */
    "".to_string()
}

struct ServerConfiguration {
    static_directory: Option<String>,
}

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options]", program);
    print!("{}", opts.usage(&brief));
}

#[rocket::launch]
fn rocket_main() -> _ {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();
    let mut opts = Options::new();
    opts.optopt(
        "s",
        "static",
        "directory for static files",
        "/path/to/directory",
    );
    opts.optflag("h", "help", "print this help");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => {
            panic!("error when parsing arguments: {}", f)
        }
    };

    if matches.opt_present("h") {
        print_usage(&program, opts);
        exit(1);
    }

    let server_configuration = ServerConfiguration {
        static_directory: matches.opt_str("s"),
    };

    rocket::build()
        .attach(CORS)
        .manage(server_configuration)
        .mount("/", rocket::routes![analyze])
        .mount("/", rocket::routes![get_tree])
        .mount("/", rocket::routes![get_version])
        .mount("/", rocket::routes![ping])
        .mount("/", rocket::routes![get_options])
        .mount("/", rocket::routes![serve_static])
        .mount("/", rocket::routes![languages])
}
