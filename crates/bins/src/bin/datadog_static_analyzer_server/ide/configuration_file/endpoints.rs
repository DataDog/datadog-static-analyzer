use std::path::PathBuf;

use crate::datadog_static_analyzer_server::ide::configuration_file::models::{
    CanOnboardRequest, GetRulesetsRequest,
};

use super::error::ConfigFileError;
use super::models::{AddRuleSetsRequest, IgnoreRuleRequest};
use super::static_analysis_config_file::StaticAnalysisConfigFile;
use kernel::utils::encode_base64_string;
use rocket::http::Status;
use rocket::response::status::Custom;
use rocket::serde::json::Json;
use tracing::instrument;

// TODO: Review DEPRECATED endpoints in 6 months from now: 2025-09-03
// Considering if we want to support those endpoints for more than 6 months.
// If not, feel free to remove them.

/// Ignores a rule in the static analysis configuration file.
///
/// # Arguments
/// * `request` - The request containing the rule to ignore and the configuration file (base64).
#[instrument()]
#[rocket::post(
    "/v1/config/ignore-rule",
    format = "application/json",
    data = "<request>"
)]
pub fn post_ignore_rule(
    request: Json<IgnoreRuleRequest>,
) -> Result<String, Custom<ConfigFileError>> {
    let IgnoreRuleRequest {
        rule,
        configuration_base64,
        encoded,
        ..
    } = request.into_inner();
    tracing::debug!(rule, content = &configuration_base64);
    let result = StaticAnalysisConfigFile::with_ignored_rule(rule.into(), configuration_base64);
    to_response_result(result, encoded)
}

/// Checks if onboarding is allowed for the configuration file (deprecated).
///
/// # Deprecation
/// Deprecated: Use [`post_can_onboard_v2`] instead.
///
/// # Arguments
/// * `content` - The path to the configuration file.
#[instrument()]
#[rocket::get("/v1/config/can-onboard/<content..>")]
pub fn get_can_onboard(content: PathBuf) -> Result<Json<bool>, Custom<ConfigFileError>> {
    let content_str = content.to_string_lossy().into_owned();
    can_onboard(content_str)
}

/// Checks if onboarding is allowed for the configuration file (v2).
///
/// # Arguments
/// * `request` - The request containing the configuration file (base64).
#[instrument()]
#[rocket::post(
    "/v2/config/can-onboard",
    format = "application/json",
    data = "<request>"
)]
pub fn post_can_onboard_v2(
    request: Json<CanOnboardRequest>,
) -> Result<Json<bool>, Custom<ConfigFileError>> {
    let CanOnboardRequest {
        configuration_base64,
        ..
    } = request.into_inner();
    can_onboard(configuration_base64)
}

/// Gets the rulesets from the static analysis configuration file (deprecated).
///
/// # Deprecation
/// Deprecated: Use [`post_get_rulesets_v2`] instead.
///
/// # Arguments
/// * `content` - The path to the configuration file.
#[instrument()]
#[rocket::get("/v1/config/rulesets/<content..>")]
pub fn get_get_rulesets(content: PathBuf) -> Json<Vec<String>> {
    let content_str = content.to_string_lossy().into_owned();
    get_rulesets(content_str)
}

/// Gets the rulesets from the static analysis configuration file (v2).
///
/// # Arguments
/// * `request` - The request containing the configuration file (base64).
#[instrument()]
#[rocket::post(
    "/v2/config/get-rulesets",
    format = "application/json",
    data = "<request>"
)]
pub fn post_get_rulesets_v2(request: Json<GetRulesetsRequest>) -> Json<Vec<String>> {
    let GetRulesetsRequest {
        configuration_base64,
        ..
    } = request.into_inner();
    get_rulesets(configuration_base64)
}

/// Adds rulesets to the static analysis configuration file (deprecated).
///
/// # Deprecation
/// Deprecated: Use [`post_add_rulesets_v2`] instead.
///
/// # Arguments
/// * `request` - The request containing rulesets and configuration file (base64).
#[instrument()]
#[rocket::post("/v1/config/rulesets", format = "application/json", data = "<request>")]
pub fn post_add_rulesets(
    request: Json<AddRuleSetsRequest>,
) -> Result<String, Custom<ConfigFileError>> {
    add_rulesets(request)
}

/// Adds rulesets to the static analysis configuration file (v2).
///
/// # Arguments
/// * `request` - The request containing rulesets and configuration file (base64).
#[instrument()]
#[rocket::post(
    "/v2/config/add-rulesets",
    format = "application/json",
    data = "<request>"
)]
pub fn post_add_rulesets_v2(
    request: Json<AddRuleSetsRequest>,
) -> Result<String, Custom<ConfigFileError>> {
    add_rulesets(request)
}

// ----------

/// Adds rulesets to the configuration file.
///
/// # Arguments
/// * `request` - The request containing rulesets and configuration file (base64).
fn add_rulesets(request: Json<AddRuleSetsRequest>) -> Result<String, Custom<ConfigFileError>> {
    let AddRuleSetsRequest {
        rulesets,
        configuration_base64,
        encoded,
        ..
    } = request.into_inner();
    tracing::debug!(
        rulesets=?&rulesets,
        content=&configuration_base64
    );
    let result = StaticAnalysisConfigFile::with_added_rulesets(&rulesets, configuration_base64);
    to_response_result(result, encoded)
}

/// Extracts rulesets from the configuration file.
///
/// # Arguments
/// * `content` - The configuration file content (base64).
fn get_rulesets(mut content: String) -> Json<Vec<String>> {
    if cfg!(target_os = "windows") {
        // NOTE: this is needed due to how Rocket works with multiple segment captures.
        // we may get rid of this once v1 endpoints are no longer needed.
        content = content.replace("\\", "/");
    }
    tracing::debug!(%content);
    Json(StaticAnalysisConfigFile::to_rulesets(content))
}

/// Checks if onboarding is allowed for the configuration file.
///
/// # Arguments
/// * `content` - The configuration file content (base64).
fn can_onboard(mut content: String) -> Result<Json<bool>, Custom<ConfigFileError>> {
    if cfg!(target_os = "windows") {
        // NOTE: this is needed due to how Rocket works with multiple segment captures.
        // we may get rid of this once v1 endpoints are no longer needed.
        content = content.replace("\\", "/");
    }
    tracing::debug!(%content);
    let config = StaticAnalysisConfigFile::try_from(content)
        .map_err(|e| Custom(Status::InternalServerError, e))?;
    let can_onboard = config.is_onboarding_allowed();
    Ok(Json(can_onboard))
}

/// Converts the result to a response string, optionally encoding it in base64.
///
/// # Arguments
/// * `result` - The result string or error.
/// * `encode` - Whether to encode the result in base64.
fn to_response_result(
    result: Result<String, ConfigFileError>,
    encode: bool,
) -> Result<String, Custom<ConfigFileError>> {
    result
        .map(|r| if encode { encode_base64_string(r) } else { r })
        .map_err(|e| Custom(Status::InternalServerError, e))
}
