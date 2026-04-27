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

/// Returns the enclosing function for the given source position, or `None` if the position
/// is not inside any named function or the language has no implementation.
///
/// This function parses the source code from scratch.
/// If you already have a parsed tree, use [`find_enclosing_function_with_tree`].
pub fn find_enclosing_function(
    source_code: &str,
    start_line: u32,
    start_col: u32,
    end_line: u32,
    end_col: u32,
    language: &Language,
) -> Option<EnclosingFunction> {
    match language {
        Language::Java => java::methods::find_enclosing_function(
            source_code,
            start_line,
            start_col,
            end_line,
            end_col,
        ),
        Language::Python
        | Language::Go
        | Language::JavaScript
        | Language::TypeScript
        | Language::Csharp
        | Language::Dockerfile
        | Language::Elixir
        | Language::Json
        | Language::Kotlin
        | Language::Ruby
        | Language::Rust
        | Language::Swift
        | Language::Terraform
        | Language::Yaml
        | Language::Starlark
        | Language::Bash
        | Language::PHP
        | Language::Markdown
        | Language::Apex
        | Language::R
        | Language::SQL => None,
    }
}

/// Returns the enclosing function for the given source position, reusing an already-parsed tree.
/// See [`find_enclosing_function`] for documentation.
pub fn find_enclosing_function_with_tree(
    source_code: &str,
    tree: &tree_sitter::Tree,
    start_line: u32,
    start_col: u32,
    end_line: u32,
    end_col: u32,
    language: &Language,
) -> Option<EnclosingFunction> {
    match language {
        Language::Java => java::methods::find_enclosing_function_with_tree(
            source_code,
            tree,
            start_line,
            start_col,
            end_line,
            end_col,
        ),
        Language::Python
        | Language::Go
        | Language::JavaScript
        | Language::TypeScript
        | Language::Csharp
        | Language::Dockerfile
        | Language::Elixir
        | Language::Json
        | Language::Kotlin
        | Language::Ruby
        | Language::Rust
        | Language::Swift
        | Language::Terraform
        | Language::Yaml
        | Language::Starlark
        | Language::Bash
        | Language::PHP
        | Language::Markdown
        | Language::Apex
        | Language::R
        | Language::SQL => None,
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
