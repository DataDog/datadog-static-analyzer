use secrets::model::secret_result::SecretResult;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSecretsRequest {
    pub filename: String,
    pub code: String,
    pub rules: Vec<Box<serde_json::value::RawValue>>,
    #[serde(default)]
    pub use_debug: bool,
    #[serde(rename = "configuration")]
    pub configuration_base64: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScanSecretsResponse {
    pub rule_responses: Vec<SecretResult>,
    pub errors: Vec<String>,
}
