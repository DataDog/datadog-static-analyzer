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
pub fn ignore_rule(
    request: Json<IgnoreRuleRequest>,
) -> Result<Json<String>, Custom<ConfigFileError>> {
    let IgnoreRuleRequest {
        rule,
        configuration_base64,
        encoded,
        ..
    } = request.into_inner();
    tracing::debug!(rule, content = &configuration_base64);
    let result = StaticAnalysisConfigFile::with_ignored_rule(rule.into(), configuration_base64);
    to_json_result(result, encoded)
}

#[instrument()]
#[rocket::post("/v1/config/rulesets", format = "application/json", data = "<request>")]
pub fn post_rulesets(
    request: Json<AddRuleSetsRequest>,
) -> Result<Json<String>, Custom<ConfigFileError>> {
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
    to_json_result(result, encoded)
}

#[instrument()]
#[rocket::get("/v1/config/rulesets/<content>", format = "application/json")]
pub fn get_rulesets(content: &str) -> Json<Vec<String>> {
    tracing::debug!(%content);
    Json(StaticAnalysisConfigFile::to_rulesets(content.to_string()))
}

#[instrument()]
#[rocket::get("/v1/config/can-onboard/<content>", format = "application/json")]
pub fn can_onboard(content: &str) -> Result<Json<bool>, Custom<ConfigFileError>> {
    tracing::debug!(%content);
    let config = StaticAnalysisConfigFile::try_from(content.to_string())
        .map_err(|e| Custom(Status::InternalServerError, e))?;
    let can_onboard = config.is_onboarding_allowed();
    Ok(Json(can_onboard))
}

fn to_json_result(
    result: Result<String, ConfigFileError>,
    encode: bool,
) -> Result<Json<String>, Custom<ConfigFileError>> {
    result
        .map(|r| if encode { encode_base64_string(r) } else { r })
        .map(Into::into)
        .map_err(|e| Custom(Status::InternalServerError, e))
}
