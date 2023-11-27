use crate::model::common::Language;
use base64::engine::general_purpose;
use base64::Engine;

use crate::model::rule_test::RuleTest;
use crate::model::violation::Violation;
use anyhow::anyhow;
use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::HashMap;
use std::fmt;

/// In the RuleCategory, we keep unknown. Old rules keep putting
/// whatever they want as category. As a matter of fact, old rules that
/// use old values (e.g. DEPLOYMENT) will fail deserialization. We then match
/// them on the `Unknown` value.
///
/// The `Unknown` value is never exposed tho because we always rewrite the
/// category of all violations by the categories of the rules they come from.
#[derive(Copy, Clone, Deserialize, Debug, Serialize, Eq, PartialEq)]
pub enum RuleCategory {
    #[serde(rename = "BEST_PRACTICES")]
    BestPractices,
    #[serde(rename = "CODE_STYLE")]
    CodeStyle,
    #[serde(rename = "ERROR_PRONE")]
    ErrorProne,
    #[serde(rename = "PERFORMANCE")]
    Performance,
    #[serde(rename = "SECURITY")]
    Security,
    #[serde(other)]
    #[serde(skip_serializing)]
    Unknown, // kept only for backward compatibility
}

impl fmt::Display for RuleCategory {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::BestPractices => write!(f, "best_practices"),
            Self::CodeStyle => write!(f, "code_style"),
            Self::ErrorProne => write!(f, "error_prone"),
            Self::Performance => write!(f, "performance"),
            Self::Security => write!(f, "security"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

#[derive(Copy, Clone, Deserialize, Debug, Serialize, Eq, PartialEq)]
pub enum RuleSeverity {
    #[serde(rename = "ERROR")]
    Error,
    #[serde(rename = "WARNING")]
    Warning,
    #[serde(rename = "NOTICE")]
    Notice,
    #[serde(rename = "NONE")]
    None,
}

impl fmt::Display for RuleSeverity {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Error => write!(f, "error"),
            Self::Warning => write!(f, "warning"),
            Self::Notice => write!(f, "notice"),
            Self::None => write!(f, "none"),
        }
    }
}

#[derive(Copy, Clone, Deserialize, Debug, Serialize, Eq, PartialEq)]
pub enum RuleType {
    #[serde(rename = "AST_CHECK")]
    AstCheck,
    #[serde(rename = "REGEX")]
    Regex,
    #[serde(rename = "TREE_SITTER_QUERY")]
    TreeSitterQuery,
}

#[derive(Copy, Clone, Deserialize, Debug, Serialize)]
pub enum EntityChecked {
    #[serde(rename = "ANY")]
    Any,
    #[serde(rename = "ASSIGNMENT")]
    Assignment,
    #[serde(rename = "CLASS_DEFINITION")]
    ClassDefinition,
    #[serde(rename = "FOR_LOOP")]
    ForLoop,
    #[serde(rename = "FUNCTION_CALL")]
    FunctionCall,
    #[serde(rename = "FUNCTION_DEFINITION")]
    FunctionDefinition,
    #[serde(rename = "FUNCTION_EXPRESSION")]
    FunctionExpression,
    #[serde(rename = "HTML_ELEMENT")]
    HtmlElement,
    #[serde(rename = "IF_STATEMENT")]
    IfStatement,
    #[serde(rename = "INTERFACE")]
    Interfacce,
    #[serde(rename = "IMPORT_STATEMENT")]
    ImportStatement,
    #[serde(rename = "VARIABLE_DECLARATION")]
    VariableDeclaration,
    #[serde(rename = "TRY_BLOCK")]
    TryBlock,
    #[serde(rename = "TYPE")]
    Type,
    #[serde(rename = "UNKNOWN")]
    Unknown,
}

// This is the rule as this is exposed to the datadog API or JSON files.
#[derive(Clone, Deserialize, Debug, Serialize, Builder)]
pub struct Rule {
    pub name: String,
    #[serde(rename = "short_description")]
    pub short_description_base64: Option<String>,
    #[serde(rename = "description")]
    pub description_base64: Option<String>,
    pub category: RuleCategory,
    pub severity: RuleSeverity,
    pub language: Language,
    pub rule_type: RuleType,
    pub entity_checked: Option<EntityChecked>,
    #[serde(rename = "code")]
    pub code_base64: String,
    pub cwe: Option<String>,
    pub checksum: String,
    pub pattern: Option<String>,
    #[serde(rename = "tree_sitter_query")]
    pub tree_sitter_query_base64: Option<String>,
    pub variables: HashMap<String, String>,
    pub tests: Vec<RuleTest>,
}

// This structure is used internally to handle rules.
// Since we do not support AST of Pattern rules anymore, we
// only have the tree-sitter query that is already pre-compiled.
#[derive(Clone, Builder, Serialize, Debug)]
pub struct RuleInternal {
    pub name: String,
    pub short_description: Option<String>,
    pub description: Option<String>,
    pub category: RuleCategory,
    pub severity: RuleSeverity,
    pub language: Language,
    pub code: String,
    pub tree_sitter_query: Option<String>,
    pub variables: HashMap<String, String>,
}

impl Rule {
    pub fn get_url(&self) -> String {
        format!(
            "https://docs.datadoghq.com/continuous_integration/static_analysis/rules/{}",
            self.name
        )
    }

    // Sometimes, the API returns an empty CWE as an empty string. If we have an empty
    // string for CWE, we set the CWE to empty.
    pub fn fix_cwe(&self) -> Rule {
        if let Some(cwe) = &self.cwe {
            if cwe.is_empty() {
                let mut new_value = self.clone();
                new_value.cwe = None;
                new_value.clone()
            } else {
                self.clone()
            }
        } else {
            self.clone()
        }
    }

    fn decode_description(&self) -> anyhow::Result<Option<String>> {
        self.description_base64
            .as_ref()
            .map(|s| {
                let bytes = general_purpose::STANDARD.decode(s)?;
                Ok(String::from_utf8(bytes)?)
            })
            .transpose()
    }

    // convert the rule to rule internal
    pub fn to_rule_internal(&self) -> anyhow::Result<RuleInternal> {
        if self.rule_type != RuleType::TreeSitterQuery {
            return Err(anyhow!("invalid rule type: {:?}", &self.rule_type));
        }
        let description = self
            .decode_description()
            .unwrap_or_else(|_| Some("invalid description".to_string()));
        let code = String::from_utf8(general_purpose::STANDARD.decode(self.code_base64.clone())?)?;
        let short_description = self
            .short_description_base64
            .as_ref()
            .map(|s| anyhow::Ok(String::from_utf8(general_purpose::STANDARD.decode(s)?)?))
            .transpose()?;

        let tree_sitter_query_code = String::from_utf8(
            general_purpose::STANDARD.decode(
                self.tree_sitter_query_base64
                    .as_ref()
                    .ok_or_else(|| anyhow!("tree sitter query is empty"))?,
            )?,
        )?;

        Ok(RuleInternal {
            name: self.name.clone(),
            short_description,
            description,
            category: self.category,
            severity: self.severity,
            language: self.language,
            code,
            tree_sitter_query: Some(tree_sitter_query_code),
            variables: self.variables.clone(),
        })
    }

    /// Check the checksum of the rule is correct. The checksum of a rule is calculated
    /// by calculating the SHA256 of the base64 of the rule code.
    pub fn verify_checksum(&self) -> bool {
        self.compute_checksum() == self.checksum
    }

    /// Compute the checksum using the SHA256 of the base64 of the rule code.
    pub fn compute_checksum(&self) -> String {
        let mut hasher = sha2::Sha256::new();
        hasher.update(self.code_base64.clone().as_bytes());
        format!("{:x}", hasher.finalize())
    }
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "rule {}", self.name)
    }
}

#[derive(Clone, Builder, Serialize, Debug)]
pub struct RuleResult {
    pub rule_name: String,
    pub filename: String,
    pub violations: Vec<Violation>,
    pub errors: Vec<String>,
    pub execution_error: Option<String>,
    pub output: Option<String>,
    pub execution_time_ms: u128,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::encode_base64_string;
    use std::collections::HashMap;

    #[test]
    fn test_checksum_valid() {
        let rule_invalid_checksum = Rule {
            name: "myrule".to_string(),
            short_description_base64: Some("bla".to_string()),
            description_base64: Some("bli".to_string()),
            category: RuleCategory::BestPractices,
            severity: RuleSeverity::Warning,
            language: Language::Python,
            rule_type: RuleType::TreeSitterQuery,
            entity_checked: None,
            code_base64: "mycode".to_string(),
            checksum: "foobar".to_string(),
            pattern: None,
            cwe: None,
            tree_sitter_query_base64: None,
            variables: HashMap::new(),
            tests: vec![],
        };
        let rule_valid_checksum = Rule {
            name: "myrule".to_string(),
            short_description_base64: Some("bla".to_string()),
            description_base64: Some("bli".to_string()),
            category: RuleCategory::BestPractices,
            severity: RuleSeverity::Warning,
            language: Language::Python,
            rule_type: RuleType::TreeSitterQuery,
            entity_checked: None,
            code_base64: encode_base64_string("rule code".to_string()),
            checksum: "3ec22eed588a89d1b2f1c967bf82041ab069ae98b3739be93ac3b22bf419f3aa"
                .to_string(),
            pattern: None,
            cwe: None,
            tree_sitter_query_base64: None,
            variables: HashMap::new(),
            tests: vec![],
        };
        assert!(!rule_invalid_checksum.verify_checksum());
        assert!(rule_valid_checksum.verify_checksum());
    }

    #[test]
    fn test_fix_cwe_cwe_empty() {
        let rule = Rule {
            name: "myrule".to_string(),
            short_description_base64: Some("bla".to_string()),
            description_base64: Some("bli".to_string()),
            category: RuleCategory::BestPractices,
            severity: RuleSeverity::Warning,
            language: Language::Python,
            rule_type: RuleType::TreeSitterQuery,
            entity_checked: None,
            code_base64: "mycode".to_string(),
            checksum: "foobar".to_string(),
            pattern: None,
            cwe: None,
            tree_sitter_query_base64: None,
            variables: HashMap::new(),
            tests: vec![],
        };
        let fixed_ruled = rule.fix_cwe();
        assert!(fixed_ruled.cwe.is_none());
    }

    #[test]
    fn test_fix_cwe_cwe_empty_string() {
        let rule = Rule {
            name: "myrule".to_string(),
            short_description_base64: Some("bla".to_string()),
            description_base64: Some("bli".to_string()),
            category: RuleCategory::BestPractices,
            severity: RuleSeverity::Warning,
            language: Language::Python,
            rule_type: RuleType::TreeSitterQuery,
            entity_checked: None,
            code_base64: "mycode".to_string(),
            checksum: "foobar".to_string(),
            pattern: None,
            cwe: Some("".to_string()),
            tree_sitter_query_base64: None,
            variables: HashMap::new(),
            tests: vec![],
        };
        let fixed_ruled = rule.fix_cwe();
        assert!(fixed_ruled.cwe.is_none());
    }

    #[test]
    fn test_fix_cwe_cwe_non_empty_string() {
        let rule = Rule {
            name: "myrule".to_string(),
            short_description_base64: Some("bla".to_string()),
            description_base64: Some("bli".to_string()),
            category: RuleCategory::BestPractices,
            severity: RuleSeverity::Warning,
            language: Language::Python,
            rule_type: RuleType::TreeSitterQuery,
            entity_checked: None,
            code_base64: "mycode".to_string(),
            checksum: "foobar".to_string(),
            pattern: None,
            cwe: Some("1234".to_string()),
            tree_sitter_query_base64: None,
            variables: HashMap::new(),
            tests: vec![],
        };
        let fixed_ruled = rule.fix_cwe();
        assert!(fixed_ruled.cwe.is_some());
    }
}
