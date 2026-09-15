// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026 Datadog, Inc.

use crate::model::secret_result::SecretResult;
use common::model::language::Language;
use common::tree_sitter::get_tree;
use lazy_static::lazy_static;
use std::collections::HashMap;
use tree_sitter::Node;

/// AST node kinds (shared by the JavaScript and TSX tree-sitter grammars) that represent a
/// string literal, a piece of one, or a comment.
const JS_TS_STRING_OR_COMMENT_NODE_KINDS: &[&str] =
    &["string", "string_fragment", "template_string", "comment"];

/// AST node kinds for Java: string/text-block literals and their fragments, interpolation and
/// template expressions, character literals, and comments.
const JAVA_STRING_OR_COMMENT_NODE_KINDS: &[&str] = &[
    "string_literal",
    "string_fragment",
    "multiline_string_fragment",
    "string_interpolation",
    "template_expression",
    "character_literal",
    "comment",
    "line_comment",
    "block_comment",
];

/// AST node kinds for Rust: string literals (including raw strings), char literals, and
/// comments.
const RUST_STRING_OR_COMMENT_NODE_KINDS: &[&str] = &[
    "string_literal",
    "raw_string_literal",
    "char_literal",
    "line_comment",
    "block_comment",
];

/// AST node kinds for C#: string literals (verbatim, raw, interpolated) and their fragments,
/// character literals, and comments.
const CSHARP_STRING_OR_COMMENT_NODE_KINDS: &[&str] = &[
    "string_literal",
    "string_literal_content",
    "string_content",
    "verbatim_string_literal",
    "raw_string_literal",
    "raw_string_start",
    "raw_string_content",
    "raw_string_end",
    "interpolated_string_expression",
    "interpolation",
    "interpolation_start",
    "interpolation_brace",
    "interpolation_quote",
    "interpolation_alignment_clause",
    "interpolation_format_clause",
    "character_literal",
    "character_literal_content",
    "comment",
];

/// AST node kinds for Python: strings (including f-strings, which share the `string` node kind)
/// and their fragments, concatenated strings, and comments.
const PYTHON_STRING_OR_COMMENT_NODE_KINDS: &[&str] = &[
    "string",
    "string_content",
    "string_start",
    "string_end",
    "interpolation",
    "escape_interpolation",
    "concatenated_string",
    "comment",
];

/// AST node kinds for PHP: strings (including encapsed strings, heredoc/nowdoc) and their
/// fragments, and comments.
const PHP_STRING_OR_COMMENT_NODE_KINDS: &[&str] = &[
    "string",
    "string_content",
    "encapsed_string",
    "nowdoc_body",
    "heredoc",
    "heredoc_start",
    "heredoc_body",
    "heredoc_end",
    "text_interpolation",
    "comment",
];

/// AST node kinds for Ruby: strings (including heredocs, `%w[]` arrays) and their fragments,
/// character literals, and comments.
const RUBY_STRING_OR_COMMENT_NODE_KINDS: &[&str] = &[
    "string",
    "string_content",
    "bare_string",
    "chained_string",
    "string_array",
    "interpolation",
    "heredoc_beginning",
    "heredoc_content",
    "heredoc_body",
    "heredoc_end",
    "character",
    "comment",
];

/// AST node kinds for Go: interpreted and raw string literals, rune literals, and comments.
const GO_STRING_OR_COMMENT_NODE_KINDS: &[&str] = &[
    "interpreted_string_literal",
    "raw_string_literal",
    "rune_literal",
    "comment",
];

/// AST node kinds for Kotlin: string literals (including multiline strings) and their
/// fragments, character literals, and comments.
const KOTLIN_STRING_OR_COMMENT_NODE_KINDS: &[&str] = &[
    "string_literal",
    "multiline_string_literal",
    "string_content",
    "interpolation",
    "character_literal",
    "line_comment",
    "block_comment",
    "multiline_comment",
];

/// AST node kinds for Elixir: strings, charlists, sigils and their fragments, char literals,
/// bitstrings, and comments.
const ELIXIR_STRING_OR_COMMENT_NODE_KINDS: &[&str] = &[
    "string",
    "charlist",
    "sigil",
    "sigil_name",
    "sigil_modifiers",
    "quoted_content",
    "interpolation",
    "bitstring",
    "char",
    "comment",
];

/// AST node kinds for Swift: string literals (line, multi-line, raw) and their text/escape
/// fragments, interpolation, and comments.
const SWIFT_STRING_OR_COMMENT_NODE_KINDS: &[&str] = &[
    "line_string_literal",
    "multi_line_string_literal",
    "raw_string_literal",
    "line_str_text",
    "multi_line_str_text",
    "str_escaped_char",
    "interpolated_expression",
    "raw_str_interpolation",
    "raw_str_interpolation_start",
    "key_path_string_expression",
    "comment",
    "multiline_comment",
];

lazy_static! {
    /// The AST node kinds that are allowed to contain a secret match, per language. Languages
    /// absent from this map are not filtered: their initial results are returned unchanged.
    static ref ALLOWED_NODE_KINDS_BY_LANGUAGE: HashMap<Language, &'static [&'static str]> = {
        let mut m = HashMap::new();
        m.insert(Language::JavaScript, JS_TS_STRING_OR_COMMENT_NODE_KINDS);
        m.insert(Language::TypeScript, JS_TS_STRING_OR_COMMENT_NODE_KINDS);
        m.insert(Language::Java, JAVA_STRING_OR_COMMENT_NODE_KINDS);
        m.insert(Language::Rust, RUST_STRING_OR_COMMENT_NODE_KINDS);
        m.insert(Language::Csharp, CSHARP_STRING_OR_COMMENT_NODE_KINDS);
        m.insert(Language::Python, PYTHON_STRING_OR_COMMENT_NODE_KINDS);
        m.insert(Language::PHP, PHP_STRING_OR_COMMENT_NODE_KINDS);
        m.insert(Language::Ruby, RUBY_STRING_OR_COMMENT_NODE_KINDS);
        m.insert(Language::Go, GO_STRING_OR_COMMENT_NODE_KINDS);
        m.insert(Language::Kotlin, KOTLIN_STRING_OR_COMMENT_NODE_KINDS);
        m.insert(Language::Elixir, ELIXIR_STRING_OR_COMMENT_NODE_KINDS);
        m.insert(Language::Swift, SWIFT_STRING_OR_COMMENT_NODE_KINDS);
        m
    };
}

/// `filter_secrets_for_ast` marks matches that are not contained within a string literal or a
/// comment by setting `is_filtered_by_ast` to true. Matches are never removed from the result.
///
/// This applies only to language in the ALLOWED_NODE_KINDS_BY_LANGUAGE map.
/// For other languages, the initial results are returned unchanged.
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
        .map(|mut result| {
            for m in result.matches.iter_mut() {
                if !is_in_allowed_node(&root_node, m.start_index, m.end_index, allowed_node_kinds) {
                    m.is_filtered_by_ast = true;
                }
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
    use crate::model::secret_result::{SecretResultMatch, SecretValidationStatus};
    use crate::model::secret_rule::RulePriority;
    use common::model::position::Position;

    fn make_result(start_index: usize, end_index: usize) -> SecretResult {
        SecretResult {
            rule_id: "rule".to_string(),
            rule_name: "rule".to_string(),
            filename: "file".to_string(),
            message: "message".to_string(),
            priority: RulePriority::Medium,
            matches: vec![SecretResultMatch {
                start: Position::new(0, 0),
                start_index,
                end: Position::new(0, 0),
                end_index,
                validation_status: SecretValidationStatus::NotValidated,
                is_suppressed: false,
                is_filtered_by_ast: false,
            }],
        }
    }

    #[test]
    fn test_flags_match_but_empty_code() {
        let code = "";
        let result = make_result(15, 35);
        let filtered = filter_secrets_for_ast(vec![result], code, &Language::JavaScript);
        assert_eq!(filtered.len(), 1);
        assert!(filtered[0].matches[0].is_filtered_by_ast);
    }

    #[test]
    fn test_keeps_match_in_string_literal() {
        let code = r#"const token = "AKIAABCDEFGHIJKLMNOP";"#;
        // "AKIAABCDEFGHIJKLMNOP" starts right after the opening quote, at byte 15.
        let result = make_result(15, 35);
        let filtered = filter_secrets_for_ast(vec![result], code, &Language::JavaScript);
        assert_eq!(filtered.len(), 1);
        assert!(!filtered[0].matches[0].is_filtered_by_ast);
    }

    #[test]
    fn test_keeps_match_in_template_string() {
        let code = r#"const token = `AKIAABCDEFGHIJKLMNOP`;"#;
        // "AKIAABCDEFGHIJKLMNOP" starts right after the opening backtick, at byte 15.
        let result = make_result(15, 35);
        let filtered = filter_secrets_for_ast(vec![result], code, &Language::JavaScript);
        assert_eq!(filtered.len(), 1);
        assert!(!filtered[0].matches[0].is_filtered_by_ast);
    }

    #[test]
    fn test_keeps_match_is_string_literal() {
        let code = r#""AKIAABCDEFGHIJKLMNOP""#;
        let result = make_result(1, 21);
        let filtered = filter_secrets_for_ast(vec![result], code, &Language::JavaScript);
        assert_eq!(filtered.len(), 1);
        assert!(!filtered[0].matches[0].is_filtered_by_ast);
    }

    #[test]
    fn test_flags_match_identifier() {
        // the code is an identifier and therefore, should be flagged as filtered
        let code = "AKIAABCDEFGHIJKLMNOP";
        let result = make_result(0, 20);
        let filtered = filter_secrets_for_ast(vec![result], code, &Language::JavaScript);
        assert_eq!(filtered.len(), 1);
        assert!(filtered[0].matches[0].is_filtered_by_ast);
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
        assert!(!filtered[0].matches[0].is_filtered_by_ast);
        assert!(filtered[1].matches[0].is_filtered_by_ast);
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
        assert!(!filtered[0].matches[0].is_filtered_by_ast);
    }

    #[test]
    fn test_keeps_match_in_comment() {
        let code = "// token AKIAABCDEFGHIJKLMNOP\nconst x = 1;";
        let result = make_result(9, 29);
        let filtered = filter_secrets_for_ast(vec![result], code, &Language::JavaScript);
        assert_eq!(filtered.len(), 1);
        assert!(!filtered[0].matches[0].is_filtered_by_ast);
    }

    #[test]
    fn test_flags_match_outside_string_or_comment() {
        let code = "const token = AKIAABCDEFGHIJKLMNOP;";
        let result = make_result(14, 34);
        let filtered = filter_secrets_for_ast(vec![result], code, &Language::JavaScript);
        assert_eq!(filtered.len(), 1);
        assert!(filtered[0].matches[0].is_filtered_by_ast);
    }

    #[test]
    fn test_returns_initial_results_for_unsupported_language() {
        let code = "token = 'AKIAABCDEFGHIJKLMNOP'";
        let result = make_result(0, 5);
        let filtered = filter_secrets_for_ast(vec![result.clone()], code, &Language::Yaml);
        assert_eq!(filtered, vec![result]);
    }

    #[test]
    fn test_java_keeps_match_in_string_literal() {
        let code = r#"String token = "AKIAABCDEFGHIJKLMNOP";"#;
        // "AKIAABCDEFGHIJKLMNOP" starts right after the opening quote, at byte 16.
        let result = make_result(16, 36);
        let filtered = filter_secrets_for_ast(vec![result], code, &Language::Java);
        assert_eq!(filtered.len(), 1);
        assert!(!filtered[0].matches[0].is_filtered_by_ast);
    }

    #[test]
    fn test_java_flags_match_identifier() {
        let code = "String token = AKIAABCDEFGHIJKLMNOP;";
        // "AKIAABCDEFGHIJKLMNOP" as a bare identifier, starting at byte 16.
        let result = make_result(16, 36);
        let filtered = filter_secrets_for_ast(vec![result], code, &Language::Java);
        assert_eq!(filtered.len(), 1);
        assert!(filtered[0].matches[0].is_filtered_by_ast);
    }

    #[test]
    fn test_rust_keeps_match_in_raw_string_literal() {
        let code = r##"let token = r#"AKIAABCDEFGHIJKLMNOP"#;"##;
        // "AKIAABCDEFGHIJKLMNOP" starts right after `r#"`, at byte 15.
        let result = make_result(15, 35);
        let filtered = filter_secrets_for_ast(vec![result], code, &Language::Rust);
        assert_eq!(filtered.len(), 1);
        assert!(!filtered[0].matches[0].is_filtered_by_ast);
    }

    #[test]
    fn test_rust_flags_match_identifier() {
        let code = "let token = AKIAABCDEFGHIJKLMNOP;";
        // "AKIAABCDEFGHIJKLMNOP" as a bare identifier, starting at byte 12.
        let result = make_result(12, 32);
        let filtered = filter_secrets_for_ast(vec![result], code, &Language::Rust);
        assert_eq!(filtered.len(), 1);
        assert!(filtered[0].matches[0].is_filtered_by_ast);
    }

    #[test]
    fn test_csharp_keeps_match_in_interpolated_string() {
        let code = r#"var token = $"AKIAABCDEFGHIJKLMNOP{suffix}";"#;
        // "AKIAABCDEFGHIJKLMNOP" starts right after `$"`, at byte 14.
        let result = make_result(14, 34);
        let filtered = filter_secrets_for_ast(vec![result], code, &Language::Csharp);
        assert_eq!(filtered.len(), 1);
        assert!(!filtered[0].matches[0].is_filtered_by_ast);
    }

    #[test]
    fn test_csharp_flags_match_identifier() {
        let code = "var token = AKIAABCDEFGHIJKLMNOP;";
        // "AKIAABCDEFGHIJKLMNOP" as a bare identifier, starting at byte 13.
        let result = make_result(13, 33);
        let filtered = filter_secrets_for_ast(vec![result], code, &Language::Csharp);
        assert_eq!(filtered.len(), 1);
        assert!(filtered[0].matches[0].is_filtered_by_ast);
    }

    #[test]
    fn test_python_keeps_match_in_fstring() {
        let code = r#"token = f"AKIAABCDEFGHIJKLMNOP{suffix}""#;
        // "AKIAABCDEFGHIJKLMNOP" starts right after `f"`, at byte 10.
        let result = make_result(10, 30);
        let filtered = filter_secrets_for_ast(vec![result], code, &Language::Python);
        assert_eq!(filtered.len(), 1);
        assert!(!filtered[0].matches[0].is_filtered_by_ast);
    }

    #[test]
    fn test_python_flags_match_identifier() {
        let code = "token = AKIAABCDEFGHIJKLMNOP";
        // "AKIAABCDEFGHIJKLMNOP" as a bare identifier, starting at byte 8.
        let result = make_result(8, 28);
        let filtered = filter_secrets_for_ast(vec![result], code, &Language::Python);
        assert_eq!(filtered.len(), 1);
        assert!(filtered[0].matches[0].is_filtered_by_ast);
    }

    #[test]
    fn test_php_keeps_match_in_heredoc() {
        let code = "<?php\n$token = <<<EOT\nAKIAABCDEFGHIJKLMNOP\nEOT;\n";
        // "AKIAABCDEFGHIJKLMNOP" starts right after the heredoc opening line, at byte 22.
        let result = make_result(22, 42);
        let filtered = filter_secrets_for_ast(vec![result], code, &Language::PHP);
        assert_eq!(filtered.len(), 1);
        assert!(!filtered[0].matches[0].is_filtered_by_ast);
    }

    #[test]
    fn test_php_flags_match_identifier() {
        let code = "<?php\nAKIAABCDEFGHIJKLMNOP;\n";
        // "AKIAABCDEFGHIJKLMNOP" as a bare identifier/constant reference, starting at byte 6.
        let result = make_result(6, 26);
        let filtered = filter_secrets_for_ast(vec![result], code, &Language::PHP);
        assert_eq!(filtered.len(), 1);
        assert!(filtered[0].matches[0].is_filtered_by_ast);
    }

    #[test]
    fn test_ruby_keeps_match_in_string_literal() {
        let code = r#"token = "AKIAABCDEFGHIJKLMNOP""#;
        // "AKIAABCDEFGHIJKLMNOP" starts right after the opening quote, at byte 9.
        let result = make_result(9, 29);
        let filtered = filter_secrets_for_ast(vec![result], code, &Language::Ruby);
        assert_eq!(filtered.len(), 1);
        assert!(!filtered[0].matches[0].is_filtered_by_ast);
    }

    #[test]
    fn test_ruby_flags_match_identifier() {
        let code = "token = AKIAABCDEFGHIJKLMNOP";
        // "AKIAABCDEFGHIJKLMNOP" as a bare identifier, starting at byte 8.
        let result = make_result(8, 28);
        let filtered = filter_secrets_for_ast(vec![result], code, &Language::Ruby);
        assert_eq!(filtered.len(), 1);
        assert!(filtered[0].matches[0].is_filtered_by_ast);
    }

    #[test]
    fn test_go_keeps_match_in_raw_string_literal() {
        let code = "var token = `AKIAABCDEFGHIJKLMNOP`";
        // "AKIAABCDEFGHIJKLMNOP" starts right after the opening backtick, at byte 13.
        let result = make_result(13, 33);
        let filtered = filter_secrets_for_ast(vec![result], code, &Language::Go);
        assert_eq!(filtered.len(), 1);
        assert!(!filtered[0].matches[0].is_filtered_by_ast);
    }

    #[test]
    fn test_go_flags_match_identifier() {
        let code = "var token = AKIAABCDEFGHIJKLMNOP";
        // "AKIAABCDEFGHIJKLMNOP" as a bare identifier, starting at byte 13.
        let result = make_result(13, 33);
        let filtered = filter_secrets_for_ast(vec![result], code, &Language::Go);
        assert_eq!(filtered.len(), 1);
        assert!(filtered[0].matches[0].is_filtered_by_ast);
    }

    #[test]
    fn test_kotlin_keeps_match_in_multiline_string() {
        let code = "val token = \"\"\"AKIAABCDEFGHIJKLMNOP\"\"\"";
        // "AKIAABCDEFGHIJKLMNOP" starts right after the opening triple quote, at byte 15.
        let result = make_result(15, 35);
        let filtered = filter_secrets_for_ast(vec![result], code, &Language::Kotlin);
        assert_eq!(filtered.len(), 1);
        assert!(!filtered[0].matches[0].is_filtered_by_ast);
    }

    #[test]
    fn test_kotlin_flags_match_identifier() {
        let code = "val token = AKIAABCDEFGHIJKLMNOP";
        // "AKIAABCDEFGHIJKLMNOP" as a bare identifier, starting at byte 13.
        let result = make_result(13, 33);
        let filtered = filter_secrets_for_ast(vec![result], code, &Language::Kotlin);
        assert_eq!(filtered.len(), 1);
        assert!(filtered[0].matches[0].is_filtered_by_ast);
    }

    #[test]
    fn test_elixir_keeps_match_in_sigil() {
        let code = "token = ~s(AKIAABCDEFGHIJKLMNOP)";
        // "AKIAABCDEFGHIJKLMNOP" starts right after the sigil opening delimiter, at byte 11.
        let result = make_result(11, 31);
        let filtered = filter_secrets_for_ast(vec![result], code, &Language::Elixir);
        assert_eq!(filtered.len(), 1);
        assert!(!filtered[0].matches[0].is_filtered_by_ast);
    }

    #[test]
    fn test_elixir_flags_match_identifier() {
        let code = "token = AKIAABCDEFGHIJKLMNOP";
        // "AKIAABCDEFGHIJKLMNOP" as a bare identifier, starting at byte 8.
        let result = make_result(8, 28);
        let filtered = filter_secrets_for_ast(vec![result], code, &Language::Elixir);
        assert_eq!(filtered.len(), 1);
        assert!(filtered[0].matches[0].is_filtered_by_ast);
    }

    #[test]
    fn test_swift_keeps_match_in_multiline_string_literal() {
        let code = "let token = \"\"\"\nAKIAABCDEFGHIJKLMNOP\n\"\"\"";
        // "AKIAABCDEFGHIJKLMNOP" starts right after the opening triple quote and newline, at byte 17.
        let result = make_result(17, 37);
        let filtered = filter_secrets_for_ast(vec![result], code, &Language::Swift);
        assert_eq!(filtered.len(), 1);
        assert!(!filtered[0].matches[0].is_filtered_by_ast);
    }

    #[test]
    fn test_swift_flags_match_identifier() {
        let code = "let token = AKIAABCDEFGHIJKLMNOP";
        // "AKIAABCDEFGHIJKLMNOP" as a bare identifier, starting at byte 13.
        let result = make_result(13, 33);
        let filtered = filter_secrets_for_ast(vec![result], code, &Language::Swift);
        assert_eq!(filtered.len(), 1);
        assert!(filtered[0].matches[0].is_filtered_by_ast);
    }

    #[test]
    fn test_java_keeps_match_in_comment() {
        let code = "// token AKIAABCDEFGHIJKLMNOP\nString x = 1;";
        let result = make_result(9, 29);
        let filtered = filter_secrets_for_ast(vec![result], code, &Language::Java);
        assert_eq!(filtered.len(), 1);
        assert!(!filtered[0].matches[0].is_filtered_by_ast);
    }

    #[test]
    fn test_rust_keeps_match_in_comment() {
        let code = "// token AKIAABCDEFGHIJKLMNOP\nlet x = 1;";
        let result = make_result(9, 29);
        let filtered = filter_secrets_for_ast(vec![result], code, &Language::Rust);
        assert_eq!(filtered.len(), 1);
        assert!(!filtered[0].matches[0].is_filtered_by_ast);
    }

    #[test]
    fn test_csharp_keeps_match_in_comment() {
        let code = "// token AKIAABCDEFGHIJKLMNOP\nvar x = 1;";
        let result = make_result(9, 29);
        let filtered = filter_secrets_for_ast(vec![result], code, &Language::Csharp);
        assert_eq!(filtered.len(), 1);
        assert!(!filtered[0].matches[0].is_filtered_by_ast);
    }

    #[test]
    fn test_python_keeps_match_in_comment() {
        let code = "# token AKIAABCDEFGHIJKLMNOP\ntoken = 1";
        // "AKIAABCDEFGHIJKLMNOP" starts right after "# token ", at byte 8.
        let result = make_result(8, 28);
        let filtered = filter_secrets_for_ast(vec![result], code, &Language::Python);
        assert_eq!(filtered.len(), 1);
        assert!(!filtered[0].matches[0].is_filtered_by_ast);
    }

    #[test]
    fn test_php_keeps_match_in_comment() {
        let code = "<?php\n// token AKIAABCDEFGHIJKLMNOP\n$x = 1;\n";
        // "AKIAABCDEFGHIJKLMNOP" starts right after "<?php\n// token ", at byte 15.
        let result = make_result(15, 35);
        let filtered = filter_secrets_for_ast(vec![result], code, &Language::PHP);
        assert_eq!(filtered.len(), 1);
        assert!(!filtered[0].matches[0].is_filtered_by_ast);
    }

    #[test]
    fn test_ruby_keeps_match_in_comment() {
        let code = "# token AKIAABCDEFGHIJKLMNOP\ntoken = 1";
        // "AKIAABCDEFGHIJKLMNOP" starts right after "# token ", at byte 8.
        let result = make_result(8, 28);
        let filtered = filter_secrets_for_ast(vec![result], code, &Language::Ruby);
        assert_eq!(filtered.len(), 1);
        assert!(!filtered[0].matches[0].is_filtered_by_ast);
    }

    #[test]
    fn test_go_keeps_match_in_comment() {
        let code = "// token AKIAABCDEFGHIJKLMNOP\nvar x = 1";
        let result = make_result(9, 29);
        let filtered = filter_secrets_for_ast(vec![result], code, &Language::Go);
        assert_eq!(filtered.len(), 1);
        assert!(!filtered[0].matches[0].is_filtered_by_ast);
    }

    #[test]
    fn test_kotlin_keeps_match_in_comment() {
        let code = "// token AKIAABCDEFGHIJKLMNOP\nval x = 1";
        let result = make_result(9, 29);
        let filtered = filter_secrets_for_ast(vec![result], code, &Language::Kotlin);
        assert_eq!(filtered.len(), 1);
        assert!(!filtered[0].matches[0].is_filtered_by_ast);
    }

    #[test]
    fn test_elixir_keeps_match_in_comment() {
        let code = "# token AKIAABCDEFGHIJKLMNOP\ntoken = 1";
        // "AKIAABCDEFGHIJKLMNOP" starts right after "# token ", at byte 8.
        let result = make_result(8, 28);
        let filtered = filter_secrets_for_ast(vec![result], code, &Language::Elixir);
        assert_eq!(filtered.len(), 1);
        assert!(!filtered[0].matches[0].is_filtered_by_ast);
    }

    #[test]
    fn test_swift_keeps_match_in_comment() {
        let code = "// token AKIAABCDEFGHIJKLMNOP\nlet x = 1";
        let result = make_result(9, 29);
        let filtered = filter_secrets_for_ast(vec![result], code, &Language::Swift);
        assert_eq!(filtered.len(), 1);
        assert!(!filtered[0].matches[0].is_filtered_by_ast);
    }
}
