// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

pub mod bridge;
pub mod common;
pub mod context;
pub use context::*;
pub mod extension;
pub(crate) mod js;
pub(crate) mod ops;
pub(crate) mod resource_watchdog;
pub(crate) mod runtime;
pub use runtime::JsRuntime;
#[allow(dead_code)]
pub mod test_utils;
pub mod v8_ds;
pub mod v8_platform;

use std::hash::{Hash, Hasher};

#[derive(Debug, Copy, Clone)]
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
    #[allow(clippy::wrong_self_convention)]
    // (This clippy lint is overridden in order to tie the `tree_sitter::Node<'a>` lifetime
    // to `&'a RawTSNode` to make it harder to do something unintended. Note that this restriction
    // is artificial because `RawTSNode` is Copy).
    unsafe fn to_node(&self) -> tree_sitter::Node<'_> {
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
        state.write_usize(ctx[0] as usize);
        state.write_usize(ctx[1] as usize);
        state.write_usize(ctx[2] as usize);
        state.write_usize(ctx[3] as usize);
        state.write_usize(self.0.id as usize);
        state.write_usize(self.0.tree as usize);
    }
}

impl Eq for RawTSNode {}
impl PartialEq for RawTSNode {
    fn eq(&self, other: &Self) -> bool {
        self.0.id == other.0.id && self.0.context == other.0.context && self.0.tree == other.0.tree
    }
}
