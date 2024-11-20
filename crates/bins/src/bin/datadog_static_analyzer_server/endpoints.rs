use std::path::Path;

use crate::datadog_static_analyzer_server::fairings::TraceSpan;
use rocket::{
    fs::NamedFile,
    futures::FutureExt,
    http::Status,
    serde::json::{json, Json, Value},
    Build, Rocket, Shutdown, State,
};
use server::model::{
    analysis_request::AnalysisRequest, tree_sitter_tree_request::TreeSitterRequest,
};
use server::request::process_analysis_request;
use server::tree_sitter_tree::process_tree_sitter_tree_request;
use thiserror::Error;

use crate::datadog_static_analyzer_server::state::ServerState;

use super::{ide::ide_routes, utils};

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
fn shutdown_get(state: &State<ServerState>) -> Status {
    if state.is_shutdown_enabled {
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
fn shutdown_post(state: &State<ServerState>, shutdown: Shutdown) -> Status {
    if state.is_shutdown_enabled {
        shutdown.notify();
        Status::NoContent
    } else {
        Status::Forbidden
    }
}

/// Gets a list of supported languages.
#[rocket::get("/languages", format = "application/json")]
fn languages(span: TraceSpan) -> Value {
    let _entered = span.enter();
    let languages: Vec<Value> = kernel::model::common::ALL_LANGUAGES
        .iter()
        .map(|x| json!(x))
        .collect();
    json!(languages)
}

#[allow(unreachable_code)]
#[rocket::post("/analyze", format = "application/json", data = "<request>")]
fn analyze(span: TraceSpan, request: Json<AnalysisRequest>) -> Value {
    let _entered = span.enter();
    tracing::debug!("{:?}", &request.0);
    json!(process_analysis_request(request.into_inner(), todo!()))
}

#[rocket::post("/get-treesitter-ast", format = "application/json", data = "<request>")]
fn get_tree(span: TraceSpan, request: Json<TreeSitterRequest>) -> Value {
    let _entered = span.enter();
    tracing::debug!("{:?}", &request.0);
    json!(process_tree_sitter_tree_request(request.into_inner()))
}

#[rocket::get("/version", format = "text/plain")]
pub fn get_version() -> String {
    utils::get_version()
}

#[rocket::get("/revision", format = "text/plain")]
pub fn get_revision() -> String {
    utils::get_revision()
}

#[rocket::get("/static/<name>")]
async fn serve_static(
    span: TraceSpan,
    server_configuration: &State<ServerState>,
    name: &str,
) -> Option<NamedFile> {
    let _entered = span.enter();
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
const fn get_options() -> String {
    /* Intentionally left empty */
    String::new()
}

/// Simple ping method that will return "pong" as response.
#[rocket::get("/ping", format = "text/plain")]
fn ping() -> String {
    "pong".to_string()
}

fn mount_endpoints(rocket: Rocket<Build>) -> Rocket<Build> {
    rocket
        .mount(
            "/",
            rocket::routes![
                analyze,
                get_tree,
                get_version,
                get_revision,
                ping,
                get_options,
                serve_static,
                languages,
                shutdown_get,
                shutdown_post
            ],
        )
        // IDE owned routes
        .mount("/ide", ide_routes())
}

#[derive(Debug, Error)]
pub enum EndpointError {
    #[error("Error trying to start the rocket thread")]
    JoinHandleError,
    #[error("Rocket error {0:?}")]
    RocketError(#[from] rocket::Error),
    #[error("Error from exit code {0:?}")]
    ExitCode(i32),
}

impl From<i32> for EndpointError {
    fn from(value: i32) -> Self {
        Self::ExitCode(value)
    }
}

/// Starts the rocket with endpoints
pub async fn launch_rocket_with_endpoints(
    rocket: Rocket<Build>,
    tx_rocket_shutdown: rocket::tokio::sync::mpsc::Sender<Shutdown>,
) -> Result<(), EndpointError> {
    let ignited = mount_endpoints(rocket).ignite().await?;
    let shutdown_handle = ignited.shutdown();
    let rocket_handle = rocket::tokio::spawn(async { ignited.launch().await });

    let _ = tx_rocket_shutdown.send(shutdown_handle.clone()).await;
    // Will shutdown if the keep alive option has been passed
    // or if the rocket thread stops.
    rocket::futures::select! {
        a = shutdown_handle.fuse() => Ok(a),
        b = rocket_handle.fuse() => match b {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(e)) => Err(e.into()),
            Err(_) => Err(EndpointError::JoinHandleError),
        }
    }
}
