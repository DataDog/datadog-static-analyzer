use kernel::model::common::Language;
use serde_derive::{Deserialize, Serialize};

#[derive(Clone, Deserialize, Debug, Serialize)]
pub struct TreeSitterRequest {
    pub language: Language,
    pub file_encoding: String,
    #[serde(rename = "code")]
    pub code_base64: String,
}
