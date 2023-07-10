use crate::model::violation::ServerViolation;
use serde::{Deserialize, Serialize};

#[derive(Clone, Deserialize, Debug, Serialize)]
pub struct RuleResponse {
    pub identifier: String,
    pub violations: Vec<ServerViolation>,
    pub errors: Vec<String>,
    pub execution_error: Option<String>,
    pub output: Option<String>,
    pub execution_time_ms: u128,
}

#[derive(Clone, Deserialize, Debug, Serialize)]
pub struct AnalysisResponse {
    pub rule_responses: Vec<RuleResponse>,
    pub errors: Vec<String>,
}
