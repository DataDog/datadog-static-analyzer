use crate::model::common::Position;
use derive_builder::Builder;
use serde::{Deserialize, Serialize};

use std::collections::HashMap;

pub const ERROR_RULE_TIMEOUT: &str = "rule-timeout";
pub const ERROR_RULE_EXECUTION: &str = "error-execution";
pub const ERROR_RULE_CODE_TOO_BIG: &str = "error-code-too-big";
pub const ERROR_INVALID_QUERY: &str = "error-invalid-query";

// Used internally to pass options to the analysis
#[derive(Clone, Deserialize, Debug, Serialize, Builder)]
pub struct AnalysisOptions {
    pub log_output: bool,
    pub use_debug: bool,
}

// Used only internally
pub struct AnalysisContext {
    pub tree_sitter_tree: tree_sitter::Tree,
}

// Used for the node and this is externally visible.
// This is what you see when you do a .context on a node.
#[derive(Clone, Deserialize, Debug, Serialize, Builder)]
pub struct MatchNodeContext {
    pub code: Option<String>,
    pub filename: String,
    pub variables: HashMap<String, String>,
}

// The node used to capture data in tree-sitter
#[derive(Clone, Deserialize, Debug, Serialize, Builder)]
pub struct TreeSitterNode {
    #[serde(rename = "astType")]
    pub ast_type: String,
    pub start: Position,
    pub end: Position,
    #[serde(rename = "fieldName")]
    pub field_name: Option<String>,
    pub children: Vec<TreeSitterNode>,
}

// The node that is then passed to the visit function.
#[derive(Clone, Debug, Serialize, Builder)]
pub struct MatchNode {
    pub captures: HashMap<String, TreeSitterNode>,
    #[serde(rename = "capturesList")]
    pub captures_list: HashMap<String, Vec<TreeSitterNode>>,
    pub context: MatchNodeContext,
}
