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

/// Returns the name of the innermost function or method enclosing the given source position
/// for the specified language, or `None` if the position is not inside any named function or
/// the language does not have a specific implementation.
pub fn find_enclosing_function(
    source_code: &str,
    tree: &tree_sitter::Tree,
    line: u32,
    col: u32,
    language: &Language,
) -> Option<String> {
    match language {
        Language::Python => python::methods::find_enclosing_function(source_code, tree, line, col),
        Language::Java => java::methods::find_enclosing_function(source_code, tree, line, col),
        Language::Go => go::methods::find_enclosing_function(source_code, tree, line, col),
        Language::JavaScript => {
            javascript::methods::find_enclosing_function(source_code, tree, line, col)
        }
        Language::TypeScript => {
            typescript::methods::find_enclosing_function(source_code, tree, line, col)
        }
        Language::Csharp => csharp::methods::find_enclosing_function(source_code, tree, line, col),
        _ => None,
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
