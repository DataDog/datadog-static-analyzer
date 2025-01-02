// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

pub mod csharp;
pub mod go;
pub mod java;
pub mod javascript;
pub mod python;

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
