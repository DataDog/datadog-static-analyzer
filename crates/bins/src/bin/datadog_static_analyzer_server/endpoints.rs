use std::cell::Cell;
use std::path::Path;

use crate::datadog_static_analyzer_server::fairings::TraceSpan;
use crate::datadog_static_analyzer_server::rule_cache::cached_analysis_request;
use crate::{RAYON_POOL, RULE_CACHE, V8_PLATFORM};
use kernel::analysis::ddsa_lib::JsRuntime;
use rocket::{
    fs::NamedFile,
    futures::FutureExt,
    http::Status,
    serde::json::{json, Json, Value},
    Build, Rocket, Shutdown, State,
};
use server::model::analysis_request::ServerRule;
use server::model::analysis_response::AnalysisResponse;
use server::model::secret_scan::{SecretScanRequest, SecretScanResponse};
use server::model::{
    analysis_request::AnalysisRequest, tree_sitter_tree_request::TreeSitterRequest,
};
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

#[rocket::post("/analyze", format = "application/json", data = "<request>")]
async fn analyze(
    span: TraceSpan,
    state: &State<ServerState>,
    request: Json<AnalysisRequest<ServerRule>>,
) -> Value {
    let _entered = span.enter();

    let timeout = state.rule_timeout_ms;

    rocket::tokio::task::spawn_blocking(move || {
        let pool = RAYON_POOL.get().expect("pool should have been created");
        pool.scope_fifo(|_| {
            thread_local! {
                // (`Cell` is used to allow lazy instantiation of a thread local with zero runtime cost).
                static JS_RUNTIME: Cell<Option<JsRuntime>> = const { Cell::new(None) };
            }
            let mut opt = JS_RUNTIME.replace(None);
            let runtime_ref = opt.get_or_insert_with(|| {
                let v8 = V8_PLATFORM.get().expect("v8 should have been initialized");
                v8.try_new_runtime().expect("ddsa init should succeed")
            });
            let request = request.into_inner();
            let (rule_responses, errors) =
                match cached_analysis_request(runtime_ref, request, timeout, RULE_CACHE.get()) {
                    Ok(resp) => (resp, vec![]),
                    Err(err) => (vec![], vec![err.to_string()]),
                };

            JS_RUNTIME.replace(opt);

            json!(AnalysisResponse {
                rule_responses,
                errors,
            })
        })
    })
    .await
    .unwrap()
}

/// Scans source code for secrets using the provided detection rules.
///
/// This endpoint accepts a code snippet, filename, and a set of secret detection rules,
/// then scans the code to identify potential secrets like API keys, passwords, tokens, etc.
///
/// # Security Considerations
///
/// - Validates filename to prevent path traversal attacks (blocks `..` and null bytes)
/// - Enforces a maximum code size limit to prevent DoS attacks
/// - Limits the number of rules that can be processed in a single request
#[rocket::post("/scan-secrets", format = "application/json", data = "<request>")]
async fn scan_secrets(span: TraceSpan, request: Json<SecretScanRequest>) -> Value {
    let _entered = span.enter();

    rocket::tokio::task::spawn_blocking(move || {
        let start = std::time::Instant::now();
        let req = request.into_inner();

        // Maximum code size to prevent memory exhaustion and DoS attacks.
        // 10MB is sufficient for most source files while preventing abuse.
        const MAX_CODE_SIZE: usize = 10 * 1024 * 1024;

        // Maximum number of rules per request to prevent excessive CPU usage.
        // 1000 rules should be sufficient for comprehensive secret detection.
        const MAX_RULES_COUNT: usize = 1000;

        // Perform validation and processing, collecting errors instead of early returns
        let result: Result<SecretScanResponse, String> = (|| {
            // Validate filename (prevent path traversal attacks)
            if req.filename.contains("..") || req.filename.contains('\0') {
                return Err("Invalid filename: path traversal detected".to_string());
            }

            // Validate code size (prevent DoS attacks via large payloads)
            if req.code.len() > MAX_CODE_SIZE {
                return Err(format!(
                    "Code too large: {} bytes exceeds maximum of {} bytes",
                    req.code.len(),
                    MAX_CODE_SIZE
                ));
            }

            // Deserialize rules from JSON
            let rules: Vec<secrets::model::secret_rule::SecretRule> = req
                .rules
                .iter()
                .map(|r| serde_json::from_value(r.clone()))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| format!("Failed to parse rules: {}", e))?;

            // Validate rules count (prevent excessive CPU usage)
            if rules.is_empty() {
                return Err("No rules provided".to_string());
            }

            if rules.len() > MAX_RULES_COUNT {
                return Err(format!(
                    "Too many rules: {} exceeds maximum of {}",
                    rules.len(),
                    MAX_RULES_COUNT
                ));
            }

            // Build the scanner with the provided rules
            let scanner = secrets::scanner::build_sds_scanner(&rules, req.use_debug);

            // Configure analysis options
            let options = common::analysis_options::AnalysisOptions {
                use_debug: req.use_debug,
                ..Default::default()
            };

            // Perform the secret scan
            let results = secrets::scanner::find_secrets(
                &scanner,
                &rules,
                &req.filename,
                &req.code,
                &options,
            );

            // Serialize results, collecting any serialization errors separately
            let mut serialization_errors = Vec::new();
            let serialized_results: Vec<serde_json::Value> = results
                .iter()
                .filter_map(|r| match serde_json::to_value(r) {
                    Ok(value) => Some(value),
                    Err(e) => {
                        serialization_errors.push(format!(
                            "Failed to serialize result for rule '{}': {}",
                            r.rule_id, e
                        ));
                        None
                    }
                })
                .collect();

            let duration = start.elapsed();

            Ok(SecretScanResponse {
                results: serialized_results,
                errors: serialization_errors,
                execution_time_ms: duration.as_millis() as u64,
            })
        })();

        // Convert Result to final response
        let duration = start.elapsed();
        match result {
            Ok(response) => json!(response),
            Err(error) => json!(SecretScanResponse {
                results: vec![],
                errors: vec![error],
                execution_time_ms: duration.as_millis() as u64,
            }),
        }
    })
    .await
    .unwrap()
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
                scan_secrets,
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
    RocketError(Box<rocket::Error>),
    #[error("Error from exit code {0:?}")]
    ExitCode(i32),
}

impl From<rocket::Error> for EndpointError {
    fn from(value: rocket::Error) -> Self {
        Self::RocketError(Box::new(value))
    }
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
