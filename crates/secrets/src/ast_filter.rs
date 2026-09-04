// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026 Datadog, Inc.

use crate::InternalResult;
use common::model::language::Language;
use common::tree_sitter::get_tree;
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

/// `filter_secrets_for_ast` marks matches that are not contained within a string literal or a
/// comment by setting `is_filtered_by_ast` to true. Matches are never removed from the result.
///
/// This applies only to language in the ALLOWED_NODE_KINDS_BY_LANGUAGE map.
/// For other languages, the initial results are returned unchanged.
pub(crate) fn filter_secrets_for_ast(
    initial_results: Vec<InternalResult>,
    file_content: &str,
    language: &Language,
) -> Vec<InternalResult> {
    let Some(allowed_node_kinds) = ALLOWED_NODE_KINDS_BY_LANGUAGE.get(language) else {
        return initial_results;
    };

    let Some(tree) = get_tree(file_content, language) else {
        return initial_results;
    };
    let root_node = tree.root_node();

    initial_results
        .into_iter()
        .map(|mut result| {
            if !is_in_allowed_node(
                &root_node,
                result.start_index,
                result.end_index,
                allowed_node_kinds,
            ) {
                result.filtered_by_ast = true;
            }
            result
        })
        .collect()
}

/// Returns true if the range delimited by `start` and `end` is contained in a node whose kind
/// is in `allowed_node_kinds`, or in an ERROR/MISSING node. ERROR and MISSING nodes signal an
/// incomplete or malformed parse, so we don't trust the AST enough to filter those matches out.
fn is_in_allowed_node(
    root_node: &Node,
    start_index: usize,
    end_index: usize,
    allowed_node_kinds: &[&str],
) -> bool {
    let Some(node) = root_node.descendant_for_byte_range(start_index, end_index) else {
        return false;
    };

    let mut current_node = Some(node);
    while let Some(n) = current_node {
        if n.is_error() || n.is_missing() {
            return true;
        }
        if allowed_node_kinds.contains(&n.kind()) {
            return true;
        }
        current_node = n.parent();
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::secret_result::SecretValidationStatus;
    use common::model::position::Position;

    fn make_result(start_index: usize, end_index: usize) -> InternalResult {
        InternalResult {
            rule_index: 0,
            start: Position::new(0, 0),
            end: Position::new(0, 0),
            start_index,
            end_index,
            validation_status: SecretValidationStatus::NotValidated,
            filtered_by_ast: false,
        }
    }

    #[test]
    fn test_flags_match_but_empty_code() {
        let code = "";
        let result = make_result(15, 35);
        let filtered = filter_secrets_for_ast(vec![result], code, &Language::JavaScript);
        assert_eq!(filtered.len(), 1);
        assert!(filtered[0].filtered_by_ast);
    }

    #[test]
    fn test_keeps_match_in_string_literal() {
        let code = r#"const token = "AKIAABCDEFGHIJKLMNOP";"#;
        // "AKIAABCDEFGHIJKLMNOP" starts right after the opening quote, at byte 15.
        let result = make_result(15, 35);
        let filtered = filter_secrets_for_ast(vec![result], code, &Language::JavaScript);
        assert_eq!(filtered.len(), 1);
        assert!(!filtered[0].filtered_by_ast);
    }

    #[test]
    fn test_keeps_match_in_template_string() {
        let code = r#"const token = `AKIAABCDEFGHIJKLMNOP`;"#;
        // "AKIAABCDEFGHIJKLMNOP" starts right after the opening backtick, at byte 15.
        let result = make_result(15, 35);
        let filtered = filter_secrets_for_ast(vec![result], code, &Language::JavaScript);
        assert_eq!(filtered.len(), 1);
        assert!(!filtered[0].filtered_by_ast);
    }

    #[test]
    fn test_keeps_match_is_string_literal() {
        let code = r#""AKIAABCDEFGHIJKLMNOP""#;
        let result = make_result(1, 21);
        let filtered = filter_secrets_for_ast(vec![result], code, &Language::JavaScript);
        assert_eq!(filtered.len(), 1);
        assert!(!filtered[0].filtered_by_ast);
    }

    #[test]
    fn test_flags_match_identifier() {
        // the code is an identifier and therefore, should be flagged as filtered
        let code = "AKIAABCDEFGHIJKLMNOP";
        let result = make_result(0, 20);
        let filtered = filter_secrets_for_ast(vec![result], code, &Language::JavaScript);
        assert_eq!(filtered.len(), 1);
        assert!(filtered[0].filtered_by_ast);
    }

    #[test]
    fn test_flags_only_the_identifier_match() {
        let code = "const token = \"AKIAABCDEFGHIJKLMNOP\";\nAKIAABCDEFGHIJKLMNOP;";
        // "AKIAABCDEFGHIJKLMNOP" in the string, on line 1.
        let string_match = make_result(15, 35);
        // "AKIAABCDEFGHIJKLMNOP" as a bare identifier, on line 2.
        let identifier_match = make_result(38, 58);

        let filtered = filter_secrets_for_ast(
            vec![string_match, identifier_match],
            code,
            &Language::JavaScript,
        );
        assert_eq!(filtered.len(), 2);
        assert!(!filtered[0].filtered_by_ast);
        assert!(filtered[1].filtered_by_ast);
    }

    #[test]
    fn test_keeps_match_in_error_node() {
        // Malformed syntax: tree-sitter wraps the bare identifier in an ERROR node. Since the
        // parse is broken here, we should not trust the AST enough to flag the match as filtered.
        let code = "function foo( { AKIAABCDEFGHIJKLMNOP";
        let tree = get_tree(code, &Language::JavaScript);
        // ensure the node is error
        assert!(tree.is_some());
        assert!(tree.unwrap().root_node().child(0).unwrap().is_error());
        let result = make_result(16, 36);
        let filtered = filter_secrets_for_ast(vec![result], code, &Language::JavaScript);
        assert_eq!(filtered.len(), 1);
        assert!(!filtered[0].filtered_by_ast);
    }

    #[test]
    fn test_keeps_match_in_comment() {
        let code = "// token AKIAABCDEFGHIJKLMNOP\nconst x = 1;";
        let result = make_result(9, 29);
        let filtered = filter_secrets_for_ast(vec![result], code, &Language::JavaScript);
        assert_eq!(filtered.len(), 1);
        assert!(!filtered[0].filtered_by_ast);
    }

    #[test]
    fn test_flags_match_outside_string_or_comment() {
        let code = "const token = AKIAABCDEFGHIJKLMNOP;";
        let result = make_result(14, 34);
        let filtered = filter_secrets_for_ast(vec![result], code, &Language::JavaScript);
        assert_eq!(filtered.len(), 1);
        assert!(filtered[0].filtered_by_ast);
    }

    #[test]
    fn test_returns_initial_results_for_unsupported_language() {
        let code = "token = 'AKIAABCDEFGHIJKLMNOP'";
        let result = make_result(0, 5);
        let filtered = filter_secrets_for_ast(vec![result.clone()], code, &Language::Python);
        assert_eq!(filtered, vec![result]);
    }
}
