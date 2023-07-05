use kernel::model::common::Language;
use kernel::model::rule::{EntityChecked, RuleCategory, RuleSeverity, RuleType};
use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;

// This is a copy of the rule. We are just renaming the attribute to be
// backward compatible with the existing rosie server.
#[derive(Clone, Deserialize, Debug, Serialize)]
pub struct ServerRule {
    #[serde(rename = "id")]
    pub name: String,
    #[serde(rename = "short_description")]
    pub short_description_base64: Option<String>,
    #[serde(rename = "description")]
    pub description_base64: Option<String>,
    pub category: Option<RuleCategory>,
    pub severity: Option<RuleSeverity>,
    pub language: Language,
    #[serde(rename = "type")]
    pub rule_type: RuleType,
    #[serde(rename = "entity_checked")]
    pub entity_checked: Option<EntityChecked>,
    #[serde(rename = "code")]
    pub code_base64: String,
    pub checksum: Option<String>,
    pub pattern: Option<String>,
    #[serde(rename = "tree_sitter_query")]
    pub tree_sitter_query_base64: Option<String>,
    pub variables: Option<HashMap<String, String>>,
}

#[derive(Clone, Deserialize, Debug, Serialize)]
pub struct RequestOptions {
    #[serde(rename = "useTreeSitter")]
    pub use_tree_sitter: Option<bool>,
    #[serde(rename = "logOutput")]
    pub log_output: Option<bool>,
}

#[derive(Clone, Deserialize, Debug, Serialize)]
pub struct Request {
    pub filename: String,
    pub language: Language,
    #[serde(rename = "file_encoding")]
    pub file_encoding: String,
    #[serde(rename = "code")]
    pub code_base64: String,
    pub rules: Vec<ServerRule>,
    pub options: Option<RequestOptions>,
}
