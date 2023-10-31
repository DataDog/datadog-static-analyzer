use getopts::Options;
use kernel::constants::{CARGO_VERSION, VERSION};
use lazy_static::lazy_static;
use rocket::fairing::{Fairing, Info, Kind};
use rocket::fs::NamedFile;
use rocket::futures::FutureExt;
use rocket::http::{Header, Status};
use rocket::serde::json::{json, Json, Value};
use rocket::{Build, Ignite, Request as RocketRequest, Response, Rocket, Shutdown, State};
use server::model::analysis_request::AnalysisRequest;
use server::model::tree_sitter_tree_request::TreeSitterRequest;
use server::request::process_analysis_request;
use server::tree_sitter_tree::process_tree_sitter_tree_request;
use std::path::Path;
use std::process::exit;
use std::sync::mpsc::channel;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{env, process, thread};

/// get the current timestamp
fn get_current_timestamp_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
}

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

/// The shutdown endpoint, when a GET request is received, will return a 204 code if the shutdown mechanism is enabled.
/// It will return a 403 code otherwise.
///
/// The shutdown mechanism is optional, and the user starting the server decides
/// whether to enable it or not by using the `-e` or `--enable-shutdown` flag.
///
/// # Examples
///
/// To enable this feature we should start the server with the `-e` flag.
///
/// ```sh
/// ./datadog-static-analyzer-server -p 9090 -k 30 -e
/// ```
///
/// Then if we do
/// ```sh
/// curl -i localhost:9090/shutdown
/// ````
///
/// We should receive something like this:
/// ```txt
/// HTTP/1.1 204 No Content
/// server: Rocket
/// x-content-type-options: nosniff
/// x-frame-options: SAMEORIGIN
/// permissions-policy: interest-cohort=()
/// access-control-allow-origin: *
/// access-control-allow-methods: POST, GET, PATCH, OPTIONS
/// access-control-allow-headers: *
/// access-control-allow-credentials: true
/// content-length: 0
/// date: Tue, 31 Oct 2023 08:50:17 GMT
/// ```
///
/// If the server was not started with the `-e` flag, then we should receive something like this:
/// ```txt
/// HTTP/1.1 403 Forbidden
/// content-type: text/html; charset=utf-8
/// server: Rocket
/// permissions-policy: interest-cohort=()
/// x-content-type-options: nosniff
/// x-frame-options: SAMEORIGIN
/// access-control-allow-origin: *
/// access-control-allow-methods: POST, GET, PATCH, OPTIONS
/// access-control-allow-headers: *
/// access-control-allow-credentials: true
/// content-length: 385
/// date: Tue, 31 Oct 2023 08:52:06 GMT
// ```
#[rocket::get("/shutdown")]
fn shutdown_get(server_configuration: &State<ServerConfiguration>) -> Status {
    if server_configuration.is_shutdown_enabled {
        Status::NoContent
    } else {
        Status::Forbidden
    }
}

/// The shutdown endpoint, when receiving a POST request, will SHUTDOWN the server and return a 204 code if the shutdown mechanism is enabled.
/// It will return a 403 code otherwise.
///
/// The shutdown mechanism is optional, and the user starting the server decides
/// whether to enable it or not by using the `-e` or `--enable-shutdown` flag.
///
/// Please, refer to the [`shutdown_get`] function's examples section to see how this would work.
#[rocket::post("/shutdown")]
fn shutdown_post(server_configuration: &State<ServerConfiguration>, shutdown: Shutdown) -> Status {
    if server_configuration.is_shutdown_enabled {
        shutdown.notify();
        Status::NoContent
    } else {
        Status::Forbidden
    }
}

#[rocket::get("/languages", format = "application/json")]
fn languages() -> Value {
    let languages: Vec<Value> = kernel::model::common::ALL_LANGUAGES
        .iter()
        .map(|x| json!(x))
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

#[rocket::get("/version", format = "text/plain")]
fn get_version() -> String {
    CARGO_VERSION.to_string()
}

#[rocket::get("/revision", format = "text/plain")]
fn get_revision() -> String {
    VERSION.to_string()
}

#[rocket::get("/static/<name>")]
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

/// Catches all OPTION requests in order to get the CORS related Fairing triggered.
#[rocket::options("/<_..>")]
fn get_options() -> String {
    /* Intentionally left empty */
    "".to_string()
}

struct ServerConfiguration {
    static_directory: Option<String>,
    is_shutdown_enabled: bool,
}

struct ServerState {
    last_ping_request_timestamp_ms: u128,
}

// Global value that keeps the status of the server
lazy_static! {
    static ref LAST_TIMESTAMP: Mutex<ServerState> = Mutex::new(ServerState {
        last_ping_request_timestamp_ms: get_current_timestamp_ms()
    });
}

#[rocket::get("/ping", format = "text/plain")]
fn ping() -> String {
    // at every ping request, we refresh the timestamp of the latest request
    LAST_TIMESTAMP
        .lock()
        .unwrap()
        .last_ping_request_timestamp_ms = get_current_timestamp_ms();
    "pong".to_string()
}

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options]", program);
    print!("{}", opts.usage(&brief));
}

async fn spawn_rocket(
    rocket_build: Rocket<Build>,
) -> (
    rocket::tokio::task::JoinHandle<Result<Rocket<Ignite>, rocket::error::Error>>,
    Shutdown,
) {
    let rocket = rocket_build.ignite().await.unwrap();
    let shutdown_handle = rocket.shutdown();
    (rocket::tokio::spawn(rocket.launch()), shutdown_handle)
}

#[rocket::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();
    let mut opts = Options::new();

    opts.optopt(
        "s",
        "static",
        "directory for static files",
        "/path/to/directory",
    );
    opts.optopt("p", "port", "port to run the server on", "8000");
    opts.optopt("a", "address", "address to listen on", "127.0.0.1");
    opts.optopt(
        "k",
        "keep-alive-timeout",
        "how many seconds without a request the server will exit",
        "90",
    );
    opts.optflag("e", "enable-shutdown", "enables the shutdown endpoint");
    opts.optflag("h", "help", "print this help");
    opts.optflag("v", "version", "shows the tool version");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => {
            panic!("error when parsing arguments: {}", f)
        }
    };

    if matches.opt_present("v") {
        println!("Version: {}, revision: {}", CARGO_VERSION, VERSION);
        exit(0);
    }

    if matches.opt_present("h") {
        print_usage(&program, opts);
        exit(0);
    }

    let server_configuration = ServerConfiguration {
        static_directory: matches.opt_str("s"),
        is_shutdown_enabled: matches.opt_present("e"),
    };

    let mut rocket_configuration = rocket::config::Config::default();

    // Set up the port in rocket configuration if --port is passed
    if matches.opt_present("p") {
        let port_opt = matches.opt_str("p");
        if let Some(port_str) = port_opt {
            let port_res = port_str.parse::<u16>();
            if port_res.is_err() {
                eprintln!("Invalid port argument");
                exit(1)
            }
            rocket_configuration.port = port_res.unwrap();
        }
    }

    if matches.opt_present("a") {
        let addr_opt = matches.opt_str("a");
        if let Some(addr) = addr_opt {
            rocket_configuration.address = addr.parse().expect("should be able to parse addr");
        }
    }

    // channel used to send the shutdown handler so that we can exit the server gracefully
    let (tx, rx) = channel();
    let mut is_keepalive_enabled = false;

    // if we set up the keepalive mechanism (option -k)
    //   1. Get the timeout value as parameter
    //   2. Start the thread that checks every 5 seconds if we should exit the server
    if matches.opt_present("k") {
        let keepalive_timeout_sec = matches.opt_str("k");
        if let Some(keepalive_timeout) = keepalive_timeout_sec {
            let timeout_sec = keepalive_timeout.parse::<u128>().unwrap();
            let timeout_ms = timeout_sec * 1000;
            is_keepalive_enabled = true;

            // thread that periodically checks if we should exit the server
            thread::spawn(move || {
                let shutdown_handle: Shutdown = rx.recv().unwrap();
                loop {
                    // get the latest request timestamp and the current one
                    let latest_timestamp = LAST_TIMESTAMP
                        .lock()
                        .unwrap()
                        .last_ping_request_timestamp_ms;
                    let current_timestamp = get_current_timestamp_ms();

                    if latest_timestamp > 0 && current_timestamp > latest_timestamp + timeout_ms {
                        eprintln!("exiting because of timeout, trying to exit gracefully");
                        shutdown_handle.clone().notify();
                        // we give 10 seconds for the process to terminate
                        // if it does not, we abort
                        thread::sleep(Duration::from_secs(10));
                        eprintln!("no graceful exit, aborting the process");
                        process::abort();
                    }
                    thread::sleep(Duration::from_secs(5));
                }
            });
        }
    }

    let rocket_build = rocket::custom(rocket_configuration)
        .attach(CORS)
        .manage(server_configuration)
        .mount("/", rocket::routes![analyze])
        .mount("/", rocket::routes![get_tree])
        .mount("/", rocket::routes![get_version])
        .mount("/", rocket::routes![get_revision])
        .mount("/", rocket::routes![ping])
        .mount("/", rocket::routes![get_options])
        .mount("/", rocket::routes![serve_static])
        .mount("/", rocket::routes![languages])
        .mount("/", rocket::routes![shutdown_get])
        .mount("/", rocket::routes![shutdown_post]);

    let (rocket_handle, shutdown_handle) = spawn_rocket(rocket_build).await;

    if is_keepalive_enabled {
        let _ = tx.send(shutdown_handle.clone());
        // Will shutdown if the keep alive option has been passed
        // or if the rocket thread stops.
        rocket::futures::select! {
            a = shutdown_handle.fuse() => a,
            _ = rocket_handle.fuse() => ()
        };
    } else {
        let _ = rocket_handle.await;
    }
}
