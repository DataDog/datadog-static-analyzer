use std::cell::Cell;
use std::path::Path;

use crate::datadog_static_analyzer_server::fairings::TraceSpan;
use crate::datadog_static_analyzer_server::rule_cache::cached_analysis_request;
use crate::{RAYON_POOL, RULE_CACHE, V8_PLATFORM};
use kernel::analysis::ddsa_lib::JsRuntime;
use kernel::utils::decode_base64_string;
use rocket::{
    fs::NamedFile,
    futures::FutureExt,
    http::Status,
    serde::json::{json, Json, Value},
    Build, Rocket, Shutdown, State,
};
use server::model::analysis_request::ServerRule;
use server::model::analysis_response::{AnalysisResponse, RuleResponse};
use server::model::{
    analysis_request::AnalysisRequest, tree_sitter_tree_request::TreeSitterRequest,
};
use server::tree_sitter_tree::process_tree_sitter_tree_request;
use thiserror::Error;

use crate::datadog_static_analyzer_server::state::ServerState;

use super::{ide::ide_routes, utils};

// Imports for secrets scanning
use common::analysis_options::AnalysisOptions;
use kernel::model::rule::{RuleCategory, RuleSeverity};
use kernel::model::violation::Violation;
use secrets::model::secret_result::SecretResult;
use secrets::model::secret_rule::{RulePriority, SecretRule};
use secrets::scanner::{build_sds_scanner, find_secrets};
use server::model::violation::ServerViolation;

/// Maps a RulePriority to a RuleSeverity for secrets scanning results.
/// This follows the same mapping used in the CLI.
fn map_priority_to_severity(priority: RulePriority) -> RuleSeverity {
    match priority {
        RulePriority::Info => RuleSeverity::Notice,
        RulePriority::Low => RuleSeverity::Notice,
        RulePriority::Medium => RuleSeverity::Warning,
        RulePriority::High => RuleSeverity::Error,
        RulePriority::Critical => RuleSeverity::Error,
        RulePriority::None => RuleSeverity::Notice,
    }
}

/// Converts a SecretResult to a RuleResponse for unified response format.
///
/// This allows secrets to be reported in the same format as static analysis
/// violations, making it transparent to clients whether a violation came from
/// static analysis or secrets scanning.
fn convert_secret_to_rule_response(secret: SecretResult) -> RuleResponse {
    let violations: Vec<ServerViolation> = secret
        .matches
        .into_iter()
        .map(|secret_match| {
            ServerViolation(Violation {
                start: secret_match.start,
                end: secret_match.end,
                message: format!(
                    "{} (validation: {:?})",
                    secret.message, secret_match.validation_status
                ),
                severity: map_priority_to_severity(secret.priority),
                category: RuleCategory::Security,
                fixes: vec![],
                taint_flow: None,
            })
        })
        .collect();

    RuleResponse {
        identifier: secret.rule_id,
        violations,
        errors: vec![],
        execution_error: None,
        output: None,
        execution_time_ms: 0,
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

/// Analyzes code using static analysis rules and optionally secret detection rules.
///
/// # Backward Compatibility
/// This endpoint maintains full backward compatibility. Clients that don't provide
/// the `secret_rules` field will receive only static analysis results (existing behavior).
///
/// # Request Format
/// ```json
/// {
///   "filename": "config.py",
///   "language": "Python",
///   "file_encoding": "utf-8",
///   "code": "cHJpbnQoImhlbGxvIik=",
///   "rules": [...],
///   "secret_rules": [...]  // Optional: omit for static analysis only
/// }
/// ```
///
/// # Response Format
/// ```json
/// {
///   "rule_responses": [
///     {"identifier": "python/rule1", "violations": [...]},
///     {"identifier": "aws-access-key", "violations": [...]}
///   ],
///   "errors": []
/// }
/// ```
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

            let request_inner = request.into_inner();

            // Extract secret_rules before passing to static analysis
            let secret_rules_json = request_inner.secret_rules.clone();

            // 1. Run static analysis (existing logic)
            let (mut rule_responses, mut errors) = match cached_analysis_request(
                runtime_ref,
                AnalysisRequest {
                    filename: request_inner.filename.clone(),
                    language: request_inner.language,
                    file_encoding: request_inner.file_encoding.clone(),
                    code_base64: request_inner.code_base64.clone(),
                    rules: request_inner.rules,
                    configuration_base64: request_inner.configuration_base64.clone(),
                    options: request_inner.options.clone(),
                    secret_rules: None, // Don't pass to static analysis
                },
                timeout,
                RULE_CACHE.get(),
            ) {
                Ok(resp) => (resp, vec![]),
                Err(err) => (vec![], vec![err.to_string()]),
            };

            // 2. Run secrets scanning (NEW - only if rules provided)
            if let Some(secret_rules_json) = secret_rules_json {
                // Deserialize secret rules from JSON
                let secret_rules: Result<Vec<SecretRule>, _> = secret_rules_json
                    .iter()
                    .map(|r| serde_json::from_value(r.clone()))
                    .collect();

                match secret_rules {
                    Ok(rules) if !rules.is_empty() => {
                        // Build scanner and scan for secrets
                        let scanner = build_sds_scanner(&rules, false);

                        // Decode base64 code
                        let code = match decode_base64_string(request_inner.code_base64.clone()) {
                            Ok(s) => s,
                            Err(e) => {
                                errors.push(format!("Failed to decode base64 code: {}", e));
                                String::new()
                            }
                        };

                        if !code.is_empty() {
                            let options = AnalysisOptions {
                                use_debug: request_inner
                                    .options
                                    .as_ref()
                                    .and_then(|o| o.log_output)
                                    .unwrap_or(false),
                                ..Default::default()
                            };

                            let secrets = find_secrets(
                                &scanner,
                                &rules,
                                &request_inner.filename,
                                &code,
                                &options,
                            );

                            // Convert secrets to rule responses
                            let secret_responses: Vec<RuleResponse> = secrets
                                .into_iter()
                                .map(convert_secret_to_rule_response)
                                .collect();

                            // Add to results
                            rule_responses.extend(secret_responses);
                        }
                    }
                    Ok(_) => {
                        // Empty rules array - silently skip
                    }
                    Err(e) => {
                        errors.push(format!("Failed to parse secret rules: {}", e));
                    }
                }
            }
            // If secret_rules is None, we skip secrets scanning (backward compatibility)

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
