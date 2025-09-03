use std::path::PathBuf;

use super::error::ConfigFileError;
use super::models::{AddRuleSetsRequest, IgnoreRuleRequest};
use super::static_analysis_config_file::StaticAnalysisConfigFile;
use kernel::utils::encode_base64_string;
use rocket::http::Status;
use rocket::response::status::Custom;
use rocket::serde::json::Json;
use tracing::instrument;

#[instrument()]
#[rocket::post(
    "/v1/config/ignore-rule",
    format = "application/json",
    data = "<request>"
)]
pub fn ignore_rule(request: Json<IgnoreRuleRequest>) -> Result<String, Custom<ConfigFileError>> {
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

#[instrument()]
#[rocket::post("/v1/config/rulesets", format = "application/json", data = "<request>")]
pub fn post_rulesets(request: Json<AddRuleSetsRequest>) -> Result<String, Custom<ConfigFileError>> {
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

#[instrument()]
#[rocket::get("/v1/config/rulesets/<content..>")]
pub fn get_rulesets(content: PathBuf) -> Json<Vec<String>> {
    let content_str = content.to_string_lossy().into_owned();
    tracing::debug!(%content_str);
    Json(StaticAnalysisConfigFile::to_rulesets(content_str))
}

#[instrument()]
#[rocket::get("/v1/config/can-onboard/<content..>")]
pub fn can_onboard(content: PathBuf) -> Result<Json<bool>, Custom<ConfigFileError>> {
    let content_str = content.to_string_lossy().into_owned();
    tracing::debug!(%content_str);
    let config = StaticAnalysisConfigFile::try_from(content_str)
        .map_err(|e| Custom(Status::InternalServerError, e))?;
    let can_onboard = config.is_onboarding_allowed();
    Ok(Json(can_onboard))
}

fn to_response_result(
    result: Result<String, ConfigFileError>,
    encode: bool,
) -> Result<String, Custom<ConfigFileError>> {
    result
        .map(|r| if encode { encode_base64_string(r) } else { r })
        .map_err(|e| Custom(Status::InternalServerError, e))
}
