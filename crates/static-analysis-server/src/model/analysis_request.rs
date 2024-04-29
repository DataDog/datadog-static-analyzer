use kernel::model::common::Language;
use kernel::model::rule::{Argument, EntityChecked, RuleCategory, RuleSeverity, RuleType};
use serde::{Deserialize, Serialize};

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
    pub is_testing: bool,
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
    #[serde(default)]
    pub arguments: Vec<Argument>,
}

#[derive(Clone, Deserialize, Debug, Serialize)]
pub struct AnalysisRequestOptions {
    pub use_tree_sitter: Option<bool>,
    pub log_output: Option<bool>,
}

#[derive(Clone, Deserialize, Debug, Serialize)]
pub struct AnalysisRequest {
    pub filename: String,
    pub language: Language,
    pub file_encoding: String,
    #[serde(rename = "code")]
    pub code_base64: String,
    pub rules: Vec<ServerRule>,
    #[serde(rename = "configuration")]
    pub configuration_base64: Option<String>,
    pub options: Option<AnalysisRequestOptions>,
}
