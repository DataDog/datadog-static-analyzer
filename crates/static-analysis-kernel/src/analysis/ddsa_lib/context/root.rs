// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use std::sync::Arc;

/// A stateful struct containing metadata about a ddsa rule execution.
#[derive(Debug, Default)]
pub struct RootContext {
    /// The tree-sitter tree.
    //  NOTE: With the way the tree-sitter C library implements `Tree`, this is cheap to clone and
    //        move into this [`Context`], and a reference counting pointer is not necessary.
    tree: Option<tree_sitter::Tree>,
    /// The source string that was parsed by tree-sitter to generate `tree`.
    tree_text: Option<Arc<str>>,
    /// A filename associated with a rule execution.
    filename: Option<Arc<str>>,
}

impl RootContext {
    /// Returns a reference to the text used to generate underlying `tree_sitter::Tree`, if it exists.
    pub fn get_text(&self) -> Option<&str> {
        self.tree_text.as_ref().map(AsRef::as_ref)
    }

    /// Assigns the provided text string to the context. If an existing text string was assigned, it
    /// will be returned as `Some(text)`.
    pub fn set_text(&mut self, text: Arc<str>) -> Option<Arc<str>> {
        Option::replace(&mut self.tree_text, text)
    }

    /// Returns a reference to the underlying [`tree_sitter::Tree`], if it exists.
    pub fn get_tree(&self) -> Option<&tree_sitter::Tree> {
        self.tree.as_ref()
    }

    /// Assigns the provided `tree_sitter::Tree` to the context. If an existing tree was assigned, it
    /// will be returned as `Some(tree)`.
    pub fn set_tree(&mut self, tree: tree_sitter::Tree) -> Option<tree_sitter::Tree> {
        Option::replace(&mut self.tree, tree)
    }

    /// Returns a reference to the filename assigned to the context.
    pub fn get_filename(&self) -> Option<&str> {
        self.filename.as_ref().map(AsRef::as_ref)
    }

    /// Assigns the provided filename to the context. If an existing filename was assigned, it
    /// will be returned as `Some(filename)`.
    pub fn set_filename(&mut self, filename: Arc<str>) -> Option<Arc<str>> {
        Option::replace(&mut self.filename, filename)
    }
}
