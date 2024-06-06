// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

#[allow(dead_code)]
pub mod bridge;
pub mod common;
pub mod context;
pub use context::*;
pub mod extension;
pub(crate) mod js;
pub(crate) mod ops;
pub(crate) mod runtime;
pub(crate) use runtime::JsRuntime;
#[allow(dead_code)]
mod test_utils;
pub mod v8_ds;

use std::hash::{Hash, Hasher};

#[derive(Debug, Clone)]
pub struct RawTSNode(tree_sitter::ffi::TSNode);

impl RawTSNode {
    pub fn new(node: tree_sitter::Node) -> Self {
        Self(node.into_raw())
    }

    /// Constructs a [`tree_sitter::Node`] from the raw tree-sitter node.
    ///
    /// # Safety
    /// The caller must ensure the that the [`ffi::Tree`](tree_sitter::ffi::Tree) this node comes from
    /// has not been dropped.
    unsafe fn to_node(&self) -> tree_sitter::Node {
        tree_sitter::Node::from_raw(self.0)
    }
}

impl From<tree_sitter::Node<'_>> for RawTSNode {
    fn from(value: tree_sitter::Node) -> Self {
        Self::new(value)
    }
}

impl Hash for RawTSNode {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let ctx = &self.0.context;
        state.write_u64((ctx[0] as u64) << 32 | ctx[1] as u64);
        state.write_u64((ctx[2] as u64) << 32 | ctx[3] as u64);
        state.write_u64(self.0.id as u64);
        state.write_u64(self.0.tree as u64);
    }
}

impl Eq for RawTSNode {}
impl PartialEq for RawTSNode {
    fn eq(&self, other: &Self) -> bool {
        self.0.id == other.0.id && self.0.context == other.0.context && self.0.tree == other.0.tree
    }
}
