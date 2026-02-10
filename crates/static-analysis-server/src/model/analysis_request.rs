use kernel::model::common::Language;
use kernel::model::rule::{
    compute_sha256, Argument, EntityChecked, RuleCategory, RuleInternal, RuleInternalError,
    RuleSeverity, RuleType,
};
use serde::{Deserialize, Serialize};

// This is a copy of the rule. We are just renaming the attribute to be
// backward compatible with the existing rosie server.
#[derive(Clone, Deserialize, Debug, Serialize, PartialEq, Eq)]
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
    #[serde(default)]
    pub arguments: Vec<Argument>,
}

impl ServerRule {
    /// The checksum of a rule is the SHA256 of the base64 of the rule code.
    /// Returns `true` if the checksum is valid, otherwise `false`.
    pub fn verify_checksum(&self) -> bool {
        self.checksum
            .as_ref()
            .is_some_and(|checksum| checksum == &compute_sha256(&self.code_base64))
    }
}

impl From<ServerRule> for kernel::model::rule::Rule {
    fn from(value: ServerRule) -> Self {
        Self {
            name: value.name,
            short_description_base64: value.short_description_base64,
            description_base64: value.description_base64,
            category: value.category.unwrap_or(RuleCategory::BestPractices),
            severity: value.severity.unwrap_or(RuleSeverity::Warning),
            language: value.language,
            rule_type: value.rule_type,
            cwe: None,
            entity_checked: value.entity_checked,
            code_base64: value.code_base64,
            checksum: value.checksum.unwrap_or_default(),
            pattern: value.pattern,
            tree_sitter_query_base64: value.tree_sitter_query_base64,
            arguments: value.arguments,
            tests: vec![],
            is_testing: false,
            documentation_url: None, // no need to have documentation for executing the rule
        }
    }
}

impl TryFrom<ServerRule> for RuleInternal {
    type Error = &'static str;

    fn try_from(value: ServerRule) -> Result<Self, Self::Error> {
        if !value.verify_checksum() {
            return Err(crate::constants::ERROR_CHECKSUM_MISMATCH);
        }
        let rule = kernel::model::rule::Rule::from(value.clone());
        rule.to_rule_internal().map_err(|err| match err {
            RuleInternalError::InvalidBase64(_) | RuleInternalError::InvalidUtf8(_) => {
                crate::constants::ERROR_DECODING_BASE64
            }
            RuleInternalError::InvalidRuleType(_)
            | RuleInternalError::MissingTreeSitterQuery
            | RuleInternalError::InvalidTreeSitterQuery(_) => crate::constants::ERROR_PARSING_RULE,
        })
    }
}

#[derive(Clone, Deserialize, Debug, Serialize)]
pub struct AnalysisRequestOptions {
    pub use_tree_sitter: Option<bool>,
    pub log_output: Option<bool>,
}

#[derive(Clone, Deserialize, Debug, Serialize)]
pub struct AnalysisRequest<T> {
    pub filename: String,
    pub language: Language,
    pub file_encoding: String,
    #[serde(rename = "code")]
    pub code_base64: String,
    pub rules: Vec<T>,
    #[serde(rename = "configuration")]
    pub configuration_base64: Option<String>,
    pub options: Option<AnalysisRequestOptions>,
    /// Optional secret detection rules. If provided, the endpoint will also scan for secrets.
    /// This field is backward compatible - old clients that don't provide it will only get static analysis.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_rules: Option<Vec<serde_json::Value>>,
}
