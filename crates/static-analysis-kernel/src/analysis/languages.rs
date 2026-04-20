// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

pub mod csharp;
pub mod go;
pub mod java;
pub mod javascript;
pub mod python;
pub mod typescript;

use crate::model::common::Language;
use crate::model::violation::EnclosingFunction;

/// Per-file context precomputed once and reused across all violations in the same source file.
///
/// Construct with [`LanguageFileContext::new`] before iterating over violations, then call
/// [`LanguageFileContext::find_enclosing_function`] for each one.
pub enum LanguageFileContext {
    Java(java::methods::JavaFileContext),
    /// Language has no precomputed context; falls back to the regular per-call dispatch.
    Other(Language),
}

impl LanguageFileContext {
    pub fn new(source_code: &str, tree: &tree_sitter::Tree, language: &Language) -> Self {
        match language {
            Language::Java => Self::Java(java::methods::JavaFileContext::new(source_code, tree)),
            lang => Self::Other(*lang),
        }
    }

    pub fn find_enclosing_function(
        &self,
        source_code: &str,
        tree: &tree_sitter::Tree,
        line: u32,
        col: u32,
    ) -> Option<EnclosingFunction> {
        match self {
            Self::Java(ctx) => java::methods::find_enclosing_function_with_context(
                source_code,
                tree,
                line,
                col,
                ctx,
            ),
            Self::Other(lang) => {
                find_enclosing_function_with_tree(source_code, tree, line, col, lang)
            }
        }
    }
}

/// Returns the enclosing function for the given source position, or `None` if the position
/// is not inside any named function or the language has no implementation.
///
/// This function parses the source code from scratch.
/// If you already have a parsed tree, use [`find_enclosing_function_with_tree`].
pub fn find_enclosing_function(
    source_code: &str,
    line: u32,
    col: u32,
    language: &Language,
) -> Option<EnclosingFunction> {
    match language {
        Language::Python => python::methods::find_enclosing_function(source_code, line, col),
        Language::Java => java::methods::find_enclosing_function(source_code, line, col),
        Language::Go => go::methods::find_enclosing_function(source_code, line, col),
        Language::JavaScript => {
            javascript::methods::find_enclosing_function(source_code, line, col)
        }
        Language::TypeScript => {
            typescript::methods::find_enclosing_function(source_code, line, col)
        }
        Language::Csharp => csharp::methods::find_enclosing_function(source_code, line, col),
        _ => None,
    }
}

/// Returns the enclosing function for the given source position, reusing an already-parsed tree.
/// See [`find_enclosing_function`] for documentation.
pub fn find_enclosing_function_with_tree(
    source_code: &str,
    tree: &tree_sitter::Tree,
    line: u32,
    col: u32,
    language: &Language,
) -> Option<EnclosingFunction> {
    match language {
        Language::Python => {
            python::methods::find_enclosing_function_with_tree(source_code, tree, line, col)
        }
        Language::Java => {
            java::methods::find_enclosing_function_with_tree(source_code, tree, line, col)
        }
        Language::Go => {
            go::methods::find_enclosing_function_with_tree(source_code, tree, line, col)
        }
        Language::JavaScript => {
            javascript::methods::find_enclosing_function_with_tree(source_code, tree, line, col)
        }
        Language::TypeScript => {
            typescript::methods::find_enclosing_function_with_tree(source_code, tree, line, col)
        }
        Language::Csharp => {
            csharp::methods::find_enclosing_function_with_tree(source_code, tree, line, col)
        }
        _ => None,
    }
}

/// Walks up from `node` looking for an ancestor whose `kind()` is one of `class_kinds`.
/// Returns the text of that ancestor's `name` field, or `None` if not found.
pub(crate) fn enclosing_class_name<'s>(
    source_code: &'s str,
    mut node: tree_sitter::Node<'_>,
    class_kinds: &[&str],
) -> Option<&'s str> {
    loop {
        node = node.parent()?;
        if class_kinds.contains(&node.kind()) {
            return node
                .child_by_field_name("name")
                .map(|n| ts_node_text(source_code, n));
        }
    }
}

/// Returns the text that `node` spans.
///
/// This is simply a wrapper around [`tree_sitter::Node::utf8_text`]
/// to make implementations less verbose while still documenting assumptions.
///
/// # Panics
/// This panics if the node specifies out-of-bounds indices or indices that aren't along a utf-8
/// sequence boundary. This can only happen if the provided `node` is not from a tree generated from `parsed_text`.
pub(crate) fn ts_node_text<'text>(parsed_text: &'text str, node: tree_sitter::Node) -> &'text str {
    node.utf8_text(parsed_text.as_bytes())
        .expect("node should be from `parsed_text`'s tree")
}

#[cfg(test)]
mod tests {
    use crate::model::common::{Language, ALL_LANGUAGES};

    // Languages with an enclosing-function implementation in this module.
    const SUPPORTED: &[Language] = &[
        Language::Java,
        Language::Go,
        Language::Python,
        Language::JavaScript,
        Language::TypeScript,
        Language::Csharp,
    ];

    // Languages that intentionally have no implementation yet.
    // When adding a new language to the analyzer, add it here (no detection) or to
    // SUPPORTED (detection implemented) — leaving it out causes this test to fail.
    const NOT_IMPLEMENTED: &[Language] = &[
        Language::Dockerfile,
        Language::Elixir,
        Language::Json,
        Language::Kotlin,
        Language::Ruby,
        Language::Rust,
        Language::Swift,
        Language::Terraform,
        Language::Yaml,
        Language::Starlark,
        Language::Bash,
        Language::PHP,
        Language::Markdown,
        Language::Apex,
        Language::R,
        Language::SQL,
    ];

    #[test]
    fn all_languages_accounted_for() {
        for lang in ALL_LANGUAGES {
            assert!(
                SUPPORTED.contains(lang) || NOT_IMPLEMENTED.contains(lang),
                "{lang:?} is not listed in SUPPORTED or NOT_IMPLEMENTED — \
                 either add enclosing-function detection for it or add it to NOT_IMPLEMENTED"
            );
        }
    }
}
