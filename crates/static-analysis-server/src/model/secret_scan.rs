use secrets::model::secret_result::SecretResult;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretScanRequest<T = serde_json::Value> {
    pub filename: String,
    pub data: String,
    pub rules: Vec<T>,
    #[serde(default)]
    pub use_debug: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecretScanResponse {
    pub rule_responses: Vec<SecretResult>,
    pub errors: Vec<String>,
}
