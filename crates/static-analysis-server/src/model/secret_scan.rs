use common::model::position::Position;
use secrets::model::secret_result::{SecretResult, SecretValidationStatus};
use secrets::model::secret_rule::RulePriority;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretScanRequest<T = serde_json::Value> {
    pub filename: String,
    pub code: String,
    pub rules: Vec<T>,
    #[serde(default)]
    pub use_debug: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerSecretMatch {
    pub start: Position,
    pub end: Position,
    pub validation_status: SecretValidationStatus,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecretRuleResponse {
    pub identifier: String,
    pub rule_name: String,
    pub filename: String,
    pub message: String,
    pub priority: RulePriority,
    pub matches: Vec<ServerSecretMatch>,
    #[serde(default)]
    pub errors: Vec<String>,
}

impl From<SecretResult> for SecretRuleResponse {
    fn from(result: SecretResult) -> Self {
        Self {
            identifier: result.rule_id,
            rule_name: result.rule_name,
            filename: result.filename,
            message: result.message,
            priority: result.priority,
            matches: result
                .matches
                .into_iter()
                .map(|m| ServerSecretMatch {
                    start: m.start,
                    end: m.end,
                    validation_status: m.validation_status,
                })
                .collect(),
            errors: vec![],
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecretScanResponse {
    pub rule_responses: Vec<SecretRuleResponse>,
    pub errors: Vec<String>,
}
