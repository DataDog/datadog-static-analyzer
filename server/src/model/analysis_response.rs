use kernel::model::violation::Violation;
use serde_derive::{Deserialize, Serialize};

#[derive(Clone, Deserialize, Debug, Serialize)]
pub struct RuleResponse {
    pub identifier: String,
    pub violations: Vec<Violation>,
    pub errors: Vec<String>,
    #[serde(rename = "executionError")]
    pub execution_error: Option<String>,
    pub output: Option<String>,
    #[serde(rename = "executionTimeMs")]
    pub execution_time_ms: u128,
}

#[derive(Clone, Deserialize, Debug, Serialize)]
pub struct AnalysisResponse {
    pub rule_responses: Vec<RuleResponse>,
    pub errors: Vec<String>,
}
