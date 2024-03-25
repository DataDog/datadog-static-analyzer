use super::error::ConfigFileError;
use super::models::{AddRuleSetsRequest, IgnoreRuleRequest};
use super::static_analysis_config_file::StaticAnalysisConfigFile;
use kernel::utils::encode_base64_string;
use rocket::http::Status;
use rocket::serde::json::Json;
use tracing::instrument;

#[instrument()]
#[rocket::post("/config/ignore-rule", format = "application/json", data = "<request>")]
pub fn ignore_rule(
    request: Json<IgnoreRuleRequest>,
) -> Result<Json<String>, rocket::response::status::Custom<String>> {
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
#[rocket::post("/config/rulesets", format = "application/json", data = "<request>")]
pub fn post_rulesets(
    request: Json<AddRuleSetsRequest>,
) -> Result<Json<String>, rocket::response::status::Custom<String>> {
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
#[rocket::get("/config/rulesets/<content>", format = "application/json")]
pub fn get_rulesets(content: &str) -> Json<Vec<String>> {
    tracing::debug!(%content);
    Json(StaticAnalysisConfigFile::to_rulesets(content.to_string()))
}

fn to_json_result(
    result: Result<String, ConfigFileError>,
    encode: bool,
) -> Result<Json<String>, rocket::response::status::Custom<String>> {
    result
        .map(|r| if encode { encode_base64_string(r) } else { r })
        .map(Into::into)
        .map_err(|e| rocket::response::status::Custom(Status::InternalServerError, e.to_string()))
}
