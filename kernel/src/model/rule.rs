use crate::model::common::Language;
use base64::engine::general_purpose;
use base64::Engine;

use crate::model::rule_test::RuleTest;
use crate::model::violation::Violation;
use anyhow::anyhow;
use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

#[derive(Copy, Clone, Deserialize, Debug, Serialize, PartialEq)]
pub enum RuleCategory {
    #[serde(rename = "BEST_PRACTICES")]
    BestPractices,
    #[serde(rename = "CODE_STYLE")]
    CodeStyle,
    #[serde(rename = "DEPLOYMENT")]
    Deployment,
    #[serde(rename = "DOCUMENTATION")]
    Documentation,
    #[serde(rename = "DESIGN")]
    Design,
    #[serde(rename = "ERROR_PRONE")]
    ErrorProne,
    #[serde(rename = "PERFORMANCE")]
    Performance,
    #[serde(rename = "SAFETY")]
    Safety,
    #[serde(rename = "SECURITY")]
    Security,
    #[serde(rename = "UNKNOWN")]
    Unknown,
}

#[derive(Copy, Clone, Deserialize, Debug, Serialize, PartialEq)]
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
            RuleSeverity::Error => write!(f, "error"),
            RuleSeverity::Warning => write!(f, "warning"),
            RuleSeverity::Notice => write!(f, "notice"),
            RuleSeverity::None => write!(f, "unone"),
        }
    }
}

#[derive(Copy, Clone, Deserialize, Debug, Serialize, PartialEq)]
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
        format!("https://static-analysis.datadoghq.com/{}", self.name)
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
            .unwrap_or(Some("invalid description".to_string()));
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
                    .ok_or(anyhow!("tree sitter query is empty"))?,
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
