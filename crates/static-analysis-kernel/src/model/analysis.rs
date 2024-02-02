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

// Represent the lines to ignores for a file. If we need to ignore all rules on a file, it's in the
// lines_to_ignore attribute. If it's only specific rules, it's in the rules_to_ignore
pub struct LinesToIgnore {
    pub lines_to_ignore_per_rule: HashMap<u32, Vec<String>>,
    pub lines_to_ignore: Vec<u32>,
}

impl LinesToIgnore {
    // return if a specific rule should be ignored
    // rule_name is the full rule name like rule1/rule2
    // line is the line of the violation
    // lines_to_ignore is the list of lines to ignore for all rules or per rules
    pub fn should_filter_rule(&self, rule_name: &str, line: u32) -> bool {
        if self.lines_to_ignore.contains(&line) {
            return true;
        }

        if let Some(rules) = self.lines_to_ignore_per_rule.get(&line) {
            return rules.contains(&rule_name.to_string());
        }

        false
    }
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

#[cfg(test)]
mod tests {
    use crate::model::analysis::LinesToIgnore;
    use std::collections::HashMap;

    #[test]
    fn test_lines_to_ignores() {
        let mut lines_per_rule: HashMap<u32, Vec<String>> = HashMap::new();
        lines_per_rule.insert(13, vec!["ruleset/rule".to_string()]);

        let lines_to_ignore = LinesToIgnore {
            lines_to_ignore: vec![10, 42],
            lines_to_ignore_per_rule: lines_per_rule,
        };

        assert!(!lines_to_ignore.should_filter_rule("foo/bar", 11));
        assert!(lines_to_ignore.should_filter_rule("foo/bar", 10));
        assert!(lines_to_ignore.should_filter_rule("ruleset/rule", 10));
        assert!(!lines_to_ignore.should_filter_rule("ruleset/rule", 11));
        assert!(lines_to_ignore.should_filter_rule("ruleset/rule", 13));
        assert!(!lines_to_ignore.should_filter_rule("foo/bar", 13));
    }
}
