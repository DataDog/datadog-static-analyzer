use std::cell::Cell;
use std::path::Path;

use crate::datadog_static_analyzer_server::fairings::TraceSpan;
use crate::datadog_static_analyzer_server::rule_cache::cached_analysis_request;
use crate::{RAYON_POOL, RULE_CACHE, SECRET_SCANNER_CACHE, V8_PLATFORM};
use kernel::analysis::ddsa_lib::JsRuntime;
use rocket::{
    fs::NamedFile,
    futures::FutureExt,
    http::Status,
    serde::json::{json, Json, Value},
    Build, Rocket, Shutdown, State,
};
use secrets::model::secret_result::SecretResult;
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
    let languages: Vec<Value> = common::model::language::ALL_LANGUAGES
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

fn process_secret_scan_request(
    request: SecretScanRequest,
    cache: Option<&super::secret_scanner_cache::SecretScannerCache>,
) -> Result<Vec<SecretResult>, String> {
    // Maximum number of rules per request to prevent excessive CPU usage.
    const MAX_RULES_COUNT: usize = 1000;

    if request.rules.is_empty() {
        return Err("No rules provided".to_string());
    }

    if request.rules.len() > MAX_RULES_COUNT {
        return Err(format!(
            "Too many rules: {} exceeds maximum of {}",
            request.rules.len(),
            MAX_RULES_COUNT
        ));
    }

    // Validate filename (prevent path traversal attacks)
    if request.filename.contains("..") || request.filename.contains('\0') {
        return Err("Invalid filename: path traversal detected".to_string());
    }

    // Decode the configuration, if present.
    let configuration =
        server::request::decode_secrets_configuration(request.configuration_base64)?;

    let should_filter_using_ast = configuration
        .as_ref()
        .and_then(|c| c.secrets())
        .map(|s| s.experimental_ast_filter)
        .unwrap_or(false);

    let parse_rules = |raw: &[Box<serde_json::value::RawValue>]| {
        raw.iter()
            .map(|r| serde_json::from_str(r.get()))
            .collect::<Result<Vec<secrets::model::secret_rule::SecretRule>, _>>()
            .map_err(|e| format!("Failed to parse rules: {}", e))
    };

    // Get scanner + parsed rules (from cache or fresh build)
    let (scanner, rules) = if let Some(cache) = cache {
        cache.get_or_build_with(&request.rules, request.use_debug, parse_rules)?
    } else {
        let rules = parse_rules(&request.rules)?;
        let scanner = secrets::scanner::build_sds_scanner(&rules, request.use_debug)?;
        (std::sync::Arc::new(scanner), std::sync::Arc::new(rules))
    };

    // Configure analysis options
    let options = common::analysis_options::AnalysisOptions {
        use_debug: request.use_debug,
        ..Default::default()
    };

    // Perform the secret scan
    let results = secrets::scanner::find_secrets(
        &scanner,
        &rules,
        &request.filename,
        &request.data,
        &options,
        should_filter_using_ast,
    );

    // Filter out suppressed matches and drop results with no remaining matches
    let results = results
        .into_iter()
        .filter_map(|mut r| {
            r.matches.retain(|m| !m.is_suppressed);
            if r.matches.is_empty() {
                None
            } else {
                Some(r)
            }
        })
        .collect();

    Ok(results)
}

/// Scans source code for secrets using the provided detection rules.
#[rocket::post("/scan-secrets", format = "application/json", data = "<request>")]
async fn scan_secrets(span: TraceSpan, request: Json<SecretScanRequest>) -> Value {
    let _entered = span.enter();

    rocket::tokio::task::spawn_blocking(move || {
        let request = request.into_inner();
        let (rule_responses, errors) =
            match process_secret_scan_request(request, SECRET_SCANNER_CACHE.get()) {
                Ok(resp) => (resp, vec![]),
                Err(err) => (vec![], vec![err]),
            };

        json!(SecretScanResponse {
            rule_responses,
            errors,
        })
    })
    .await
    .unwrap_or_else(|e| {
        json!(SecretScanResponse {
            rule_responses: vec![],
            errors: vec![format!("Internal error: {e}")],
        })
    })
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

#[cfg(test)]
mod secret_scan_tests {
    use super::process_secret_scan_request;
    use kernel::utils::encode_base64_string;
    use secrets::model::secret_rule::{RulePriority, SecretRule};
    use server::model::secret_scan::SecretScanRequest;

    fn aws_key_rule_json() -> Box<serde_json::value::RawValue> {
        let rule = SecretRule {
            id: "aws-key".to_string(),
            sds_id: "sds-aws-key".to_string(),
            name: "AWS key".to_string(),
            description: "detects AWS access keys".to_string(),
            pattern: "AKIA[0-9A-Z]{16}".to_string(),
            default_included_keywords: vec![],
            default_excluded_keywords: vec![],
            look_ahead_character_count: Some(30),
            priority: RulePriority::Medium,
            validators: Some(vec![]),
            validators_v2: None,
            match_validation: None,
            pattern_capture_groups: vec![],
            is_supporting_rule: false,
            suppressions: None,
        };
        serde_json::value::RawValue::from_string(serde_json::to_string(&rule).unwrap()).unwrap()
    }

    fn request_with_configuration(configuration_base64: Option<String>) -> SecretScanRequest {
        // "AKIAABCDEFGHIJKLMNOP" outside a string on line 1 (should be flagged by AST filtering
        // when enabled), and the same value inside a string literal on line 2 (should not be
        // flagged).
        let code = "const token = AKIAABCDEFGHIJKLMNOP;\nconst other = \"AKIAABCDEFGHIJKLMNOP\";"
            .to_string();
        SecretScanRequest {
            filename: "myfile.js".to_string(),
            data: code,
            rules: vec![aws_key_rule_json()],
            use_debug: false,
            configuration_base64,
        }
    }

    #[test]
    fn no_configuration_does_not_filter_using_ast() {
        let request = request_with_configuration(None);
        let results = process_secret_scan_request(request, None).expect("scan should succeed");

        let matches = &results.first().expect("one rule result").matches;
        assert_eq!(matches.len(), 2);
        assert!(matches.iter().all(|m| !m.is_filtered_by_ast));
    }

    #[test]
    fn invalid_base64_configuration_is_rejected() {
        let request = request_with_configuration(Some("not-valid-base64!!".to_string()));
        let err = process_secret_scan_request(request, None).unwrap_err();
        assert!(err.contains("base64"));
    }

    #[test]
    fn invalid_yaml_configuration_is_rejected() {
        let request =
            request_with_configuration(Some(encode_base64_string(":: not yaml".to_string())));
        let err = process_secret_scan_request(request, None).unwrap_err();
        assert!(err.contains("parse"));
    }

    #[test]
    fn configuration_with_experimental_ast_filter_filters_secrets_not_in_strings() {
        let config = "\
schema-version: v1.6
secrets:
  experimental-ast-filter: true
";
        let request = request_with_configuration(Some(encode_base64_string(config.to_string())));
        let results = process_secret_scan_request(request, None).expect("scan should succeed");

        let matches = &results.first().expect("one rule result").matches;
        assert_eq!(matches.len(), 2);

        let outside_string_match = matches
            .iter()
            .find(|m| m.start.line == 1)
            .expect("match on line 1");
        assert!(
            outside_string_match.is_filtered_by_ast,
            "match outside a string literal should be filtered"
        );

        let inside_string_match = matches
            .iter()
            .find(|m| m.start.line == 2)
            .expect("match on line 2");
        assert!(
            !inside_string_match.is_filtered_by_ast,
            "match inside a string literal should not be filtered"
        );
    }
}
