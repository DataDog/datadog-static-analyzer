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

/// The function `filter_secrets_for_ast` filters all initial results and only keep the one that
/// are contained in a string or in a comment. The function checks each results and check
/// what AST element contains the match. The match can only be in comments or string.
///
/// This function only works for JavaScript and TypeScript. For other languages, tha initial results
/// are being returned.
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
        .filter(|result| {
            result.matches.iter().all(|m| {
                is_in_allowed_node(
                    &root_node,
                    file_content,
                    &m.start,
                    &m.end,
                    allowed_node_kinds,
                )
            })
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
