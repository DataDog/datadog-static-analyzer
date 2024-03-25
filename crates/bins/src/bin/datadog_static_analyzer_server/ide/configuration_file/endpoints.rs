use super::error::ConfigFileError;
use super::models::{AddRuleSetsRequest, IgnoreRuleRequest};
use super::static_analysis_config_file::StaticAnalysisConfigFile;
use crate::datadog_static_analyzer_server::fairings::TraceSpan;
use kernel::utils::encode_base64_string;
use rocket::http::Status;
use rocket::serde::json::Json;
use tracing::instrument;

#[instrument(skip(span))]
#[rocket::post("/config/ignore-rule", format = "application/json", data = "<request>")]
pub fn ignore_rule(
    span: TraceSpan,
    request: Json<IgnoreRuleRequest>,
) -> Result<Json<String>, rocket::response::status::Custom<String>> {
    let _entered = span.enter();
    tracing::debug!("{:?}", &request.0);
    let req: IgnoreRuleRequest = request.into_inner();
    let result =
        StaticAnalysisConfigFile::with_ignored_rule(req.rule.into(), req.configuration_base64);
    to_json_result(result, req.encoded)
}

#[instrument(skip(span))]
#[rocket::post("/config/rulesets", format = "application/json", data = "<request>")]
pub fn post_rulesets(
    span: TraceSpan,
    request: Json<AddRuleSetsRequest>,
) -> Result<Json<String>, rocket::response::status::Custom<String>> {
    let _entered = span.enter();
    tracing::debug!("{:?}", &request.0);
    let req: AddRuleSetsRequest = request.into_inner();
    let result =
        StaticAnalysisConfigFile::with_added_rulesets(&req.rulesets, req.configuration_base64);
    to_json_result(result, req.encoded)
}

#[instrument(skip(span))]
#[rocket::get("/config/rulesets/<content>", format = "application/json")]
pub fn get_rulesets(span: TraceSpan, content: String) -> Json<Vec<String>> {
    let _entered = span.enter();
    Json(StaticAnalysisConfigFile::to_rulesets(content))
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
