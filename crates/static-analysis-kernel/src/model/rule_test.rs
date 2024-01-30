use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RuleTest {
    pub annotation_count: u32,
    pub filename: String,
    #[serde(rename = "code")]
    pub code_base64: String,
}
