// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026 Datadog, Inc.

use crate::model::secret_result::SecretResult;
use common::model::language::Language;
use common::model::position::Position;
use common::tree_sitter::get_tree;
use common::utils::position_utils::position_to_byte_offset;
use lazy_static::lazy_static;
use std::collections::HashMap;
use tree_sitter::Node;

/// AST node kinds (shared by the JavaScript and TSX tree-sitter grammars) that represent a
/// string literal, a piece of one, or a comment.
const JS_TS_STRING_OR_COMMENT_NODE_KINDS: &[&str] =
    &["string", "string_fragment", "template_string", "comment"];

lazy_static! {
    /// The AST node kinds that are allowed to contain a secret match, per language. Languages
    /// absent from this map are not filtered: their initial results are returned unchanged.
    static ref ALLOWED_NODE_KINDS_BY_LANGUAGE: HashMap<Language, &'static [&'static str]> = {
        let mut m = HashMap::new();
        m.insert(Language::JavaScript, JS_TS_STRING_OR_COMMENT_NODE_KINDS);
        m.insert(Language::TypeScript, JS_TS_STRING_OR_COMMENT_NODE_KINDS);
        m
    };
}

/// `filter_secrets_for_ast` post-filters secret-detection results, keeping only matches that are
/// contained within a string literal or a comment.
///
/// This currently applies only to JavaScript and TypeScript. For other languages, the initial
/// results are returned unchanged.
pub fn filter_secrets_for_ast(
    initial_results: Vec<SecretResult>,
    file_content: &str,
    language: &Language,
) -> Vec<SecretResult> {
    let Some(allowed_node_kinds) = ALLOWED_NODE_KINDS_BY_LANGUAGE.get(language) else {
        return initial_results;
    };

    let Some(tree) = get_tree(file_content, language) else {
        return initial_results;
    };
    let root_node = tree.root_node();

    initial_results
        .into_iter()
        .filter_map(|mut result| {
            result.matches.retain(|m| {
                is_in_allowed_node(
                    &root_node,
                    file_content,
                    &m.start,
                    &m.end,
                    allowed_node_kinds,
                )
            });
            if result.matches.is_empty() {
                None
            } else {
                Some(result)
            }
        })
        .collect()
}

/// Returns true if the range delimited by `start` and `end` is contained in a node whose kind
/// is in `allowed_node_kinds`.
fn is_in_allowed_node(
    root_node: &Node,
    file_content: &str,
    start: &Position,
    end: &Position,
    allowed_node_kinds: &[&str],
) -> bool {
    let (Some(start_byte), Some(end_byte)) = (
        position_to_byte_offset(file_content, start),
        position_to_byte_offset(file_content, end),
    ) else {
        return false;
    };

    let Some(node) = root_node.descendant_for_byte_range(start_byte, end_byte) else {
        return false;
    };

    let mut current_node = Some(node);
    while let Some(n) = current_node {
        let node_kind = n.kind();
        if allowed_node_kinds.contains(&node_kind) {
            return true;
        }
        current_node = n.parent();
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::secret_result::{SecretResultMatch, SecretValidationStatus};
    use crate::model::secret_rule::RulePriority;

    fn make_result(start: Position, end: Position) -> SecretResult {
        SecretResult {
            rule_id: "rule-id".to_string(),
            rule_name: "rule-name".to_string(),
            filename: "file.js".to_string(),
            message: "message".to_string(),
            priority: RulePriority::Low,
            matches: vec![SecretResultMatch {
                start,
                end,
                validation_status: SecretValidationStatus::NotValidated,
                is_suppressed: false,
            }],
        }
    }

    #[test]
    fn test_keeps_match_but_empty_code() {
        let code = "";
        let result = make_result(Position::new(1, 16), Position::new(1, 36));
        let filtered = filter_secrets_for_ast(vec![result], code, &Language::JavaScript);
        assert_eq!(filtered.len(), 0);
    }

    #[test]
    fn test_keeps_match_in_string_literal() {
        let code = r#"const token = "AKIAABCDEFGHIJKLMNOP";"#;
        // "AKIAABCDEFGHIJKLMNOP" starts at column 16 (1-based, right after the opening quote).
        let result = make_result(Position::new(1, 16), Position::new(1, 36));
        let filtered = filter_secrets_for_ast(vec![result], code, &Language::JavaScript);
        assert_eq!(filtered.len(), 1);
    }

    #[test]
    fn test_keeps_match_in_template_string() {
        let code = r#"const token = `AKIAABCDEFGHIJKLMNOP`;"#;
        // "AKIAABCDEFGHIJKLMNOP" starts at column 16 (1-based, right after the opening quote).
        let result = make_result(Position::new(1, 16), Position::new(1, 36));
        let filtered = filter_secrets_for_ast(vec![result], code, &Language::JavaScript);
        assert_eq!(filtered.len(), 1);
    }

    #[test]
    fn test_keeps_match_is_string_literal() {
        let code = r#""AKIAABCDEFGHIJKLMNOP""#;
        let result = make_result(Position::new(1, 2), Position::new(1, 22));
        let filtered = filter_secrets_for_ast(vec![result], code, &Language::JavaScript);
        assert_eq!(filtered.len(), 1);
    }

    #[test]
    fn test_no_match_identifier() {
        // the code is an identifier and therefore, should fail
        let code = "AKIAABCDEFGHIJKLMNOP";
        let result = make_result(Position::new(1, 1), Position::new(1, 21));
        let filtered = filter_secrets_for_ast(vec![result], code, &Language::JavaScript);
        assert_eq!(filtered.len(), 0);
    }

    #[test]
    fn test_filters_out_only_the_identifier_match() {
        let code = "const token = \"AKIAABCDEFGHIJKLMNOP\";\nAKIAABCDEFGHIJKLMNOP;";
        // "AKIAABCDEFGHIJKLMNOP" in the string starts at column 16 (1-based, right after the
        // opening quote) on line 1.
        let string_match = SecretResultMatch {
            start: Position::new(1, 16),
            end: Position::new(1, 36),
            validation_status: SecretValidationStatus::NotValidated,
            is_suppressed: false,
        };
        // "AKIAABCDEFGHIJKLMNOP" as a bare identifier on line 2.
        let identifier_match = SecretResultMatch {
            start: Position::new(2, 1),
            end: Position::new(2, 21),
            validation_status: SecretValidationStatus::NotValidated,
            is_suppressed: false,
        };
        let mut result = make_result(Position::new(1, 16), Position::new(1, 36));
        result.matches = vec![string_match.clone(), identifier_match];

        let filtered = filter_secrets_for_ast(vec![result], code, &Language::JavaScript);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].matches, vec![string_match]);
    }

    #[test]
    fn test_keeps_match_in_comment() {
        let code = "// token AKIAABCDEFGHIJKLMNOP\nconst x = 1;";
        let result = make_result(Position::new(1, 10), Position::new(1, 30));
        let filtered = filter_secrets_for_ast(vec![result], code, &Language::JavaScript);
        assert_eq!(filtered.len(), 1);
    }

    #[test]
    fn test_discards_match_outside_string_or_comment() {
        let code = "const token = AKIAABCDEFGHIJKLMNOP;";
        let result = make_result(Position::new(1, 15), Position::new(1, 35));
        let filtered = filter_secrets_for_ast(vec![result], code, &Language::JavaScript);
        assert!(filtered.is_empty());
    }

    #[test]
    fn test_returns_initial_results_for_unsupported_language() {
        let code = "token = 'AKIAABCDEFGHIJKLMNOP'";
        let result = make_result(Position::new(1, 1), Position::new(1, 5));
        let filtered = filter_secrets_for_ast(vec![result.clone()], code, &Language::Python);
        assert_eq!(filtered, vec![result]);
    }
}
