use super::models::{ScanSecretsRequest, ScanSecretsResponse};
use crate::SECRET_SCANNER_CACHE;
use cli::model::datadog_api::SecretRuleApiType;
use common::analysis_options::AnalysisOptions;
use kernel::utils::decode_base64_string;
use rocket::serde::json::{json, Json, Value};
use secrets::model::secret_result::SecretResult;
use secrets::model::secret_rule::SecretRule;
use tracing::instrument;

/// Scans source code for secrets from an IDE.
///
/// Validation is disabled for IDE requests so scans do not reach out to external
/// services while a user is editing a file.
#[instrument(skip(request))]
#[rocket::post("/v1/secrets/scan", format = "application/json", data = "<request>")]
pub async fn post_scan_secrets(request: Json<ScanSecretsRequest>) -> Value {
    rocket::tokio::task::spawn_blocking(move || {
        let request = request.into_inner();
        let (rule_responses, errors) = match scan(request) {
            Ok(r) => (r, vec![]),
            Err(e) => (vec![], vec![e]),
        };
        json!(ScanSecretsResponse {
            rule_responses,
            errors,
        })
    })
    .await
    .unwrap_or_else(|e| {
        json!(ScanSecretsResponse {
            rule_responses: vec![],
            errors: vec![format!("Internal error: {e}")],
        })
    })
}

fn scan(request: ScanSecretsRequest) -> Result<Vec<SecretResult>, String> {
    let cache = SECRET_SCANNER_CACHE
        .get()
        .expect("should have been initialized");

    let (scanner, rules) = cache.get_or_build_with(&request.rules, request.use_debug, |raw| {
        raw.iter()
            .map(|r| {
                let api_rule: SecretRuleApiType = serde_json::from_str(r.get())
                    .map_err(|e| format!("Failed to parse secret rule: {e}"))?;
                SecretRule::try_from(api_rule)
                    .map_err(|e| format!("Failed to convert secret rule: {e}"))
            })
            .collect::<Result<Vec<_>, _>>()
    })?;

    let options = AnalysisOptions {
        use_debug: request.use_debug,
        disable_validation: true,
        ..Default::default()
    };

    // Decode the configuration, if present.
    let configuration = if let Some(config_b64) = request.configuration_base64.clone() {
        let config = decode_base64_string(config_b64)
            .map_err(|_| "Configuration is not valid base64".to_string())?;
        let yaml = secrets::config::file_v1::parse_yaml(&config)
            .map_err(|_| "Could not parse configuration".to_string())?;

        Some(secrets::config::file_v1::ConfigFile::from(yaml))
    } else {
        None
    };

    let should_filter_using_ast = configuration
        .as_ref()
        .and_then(|c| c.secrets())
        .map(|s| s.experimental_ast_filter)
        .unwrap_or(false);

    let results = secrets::scanner::find_secrets(
        &scanner,
        &rules,
        &request.filename,
        &request.code,
        &options,
        should_filter_using_ast,
    );

    let results = results
        .into_iter()
        .filter_map(|mut r| {
            r.matches.retain(|m| !m.is_suppressed);
            (!r.matches.is_empty()).then_some(r)
        })
        .collect();

    Ok(results)
}
