// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::analysis::ddsa_lib::common::NodeId;
use crate::analysis::ddsa_lib::{bridge, runtime, RawTSNode};
use deno_core::{op2, OpState};
use std::cell::RefCell;
use std::rc::Rc;

#[op2(fast)]
pub fn op_console_push(state: &mut OpState, #[string] line: &str) {
    let console = state.borrow::<Rc<RefCell<runtime::JsConsole>>>();
    let mut console = console
        .try_borrow_mut()
        .expect("console should only be accessed via sequential executions");
    console.push(line);
}

/// Returns a string containing the text used to generate the tree-sitter tree.
///
/// # Panics
/// Panics if the [`ddsa_lib::RootContext`](crate::analysis::ddsa_lib::RootContext) has not set the tree's text.
#[op2]
#[string]
pub fn op_current_ts_tree_text(state: &OpState) -> String {
    let ctx_bridge = state.borrow::<Rc<RefCell<bridge::ContextBridge>>>();
    ctx_bridge
        .borrow()
        .ddsa_root_context()
        .get_text()
        .expect("tree text should always be `Some` during rule execution")
        .to_string()
}

/// Returns a string containing the filename of the file being scanned.
///
/// # Panics
/// Panics if the [`ddsa_lib::RootContext`](crate::analysis::ddsa_lib::RootContext) has not set the filename.
#[op2]
#[string]
pub fn op_current_filename(state: &OpState) -> String {
    let ctx_bridge = state.borrow::<Rc<RefCell<bridge::ContextBridge>>>();
    ctx_bridge
        .borrow()
        .ddsa_root_context()
        .get_filename()
        .expect("filename should always be `Some` during rule execution")
        .to_string()
}

/// Returns a string containing the text that spans a tree-sitter node.
///
/// # Panics
/// Panics if the [`ddsa_lib::RootContext`](crate::analysis::ddsa_lib::RootContext) has not set the tree's text.
#[op2]
#[string]
pub fn op_ts_node_text(state: &OpState, #[smi] node_id: u32) -> Option<String> {
    let ctx_bridge = state
        .borrow::<Rc<RefCell<bridge::ContextBridge>>>()
        .borrow();
    let tree_text = ctx_bridge
        .ddsa_root_context()
        .get_text()
        .expect("tree text should always be `Some` during rule execution");
    let node_bridge = state.borrow::<Rc<RefCell<bridge::TsNodeBridge>>>().borrow();
    let safe_raw_ts_node = OpSafeRawTSNode::try_new(&node_bridge, node_id)?;
    let ts_node = safe_raw_ts_node.to_node();
    tree_text
        .get(ts_node.start_byte()..ts_node.end_byte())
        .map(ToString::to_string)
}

/// A newtype wrapper over a [`RawTSNode`] that guarantees safe generation of a [`tree_sitter::Node`].
///
/// Whereas `RawTSNode` is not inherently safe to convert to a `tree_sitter::Node`, because of how
/// we manage the tree's lifetime, it's guaranteed to be safe to access this during an op (i.e. during JavaScript execution).
struct OpSafeRawTSNode(RawTSNode);

impl OpSafeRawTSNode {
    /// Creates an `OpSafeRawTSNode` if the `node_id` exists on the [`TsNodeBridge`](bridge::TsNodeBridge).
    pub fn try_new(bridge: &bridge::TsNodeBridge, node_id: NodeId) -> Option<Self> {
        bridge.get_raw(node_id).cloned().map(Self)
    }

    /// Returns a `tree_sitter::Node` representing this raw node.
    pub fn to_node(&self) -> tree_sitter::Node {
        // Safety:
        // 1. An `OpSafeRawTSNode` can only be created by fetching a `RawTsNode` from the `bridge::TsNodeBridge`,
        //    which guarantees that its `v8::Value` counterpart exists within the v8 context. Even though the
        //    requested `node_id` can be arbitrarily modified by JavaScript, a `RawTsNode` will only be
        //    returned if we explicitly added it to the bridge via Rust, making it impossible for this function
        //    to access unintended memory.
        // 2. An op will only be called during a JavaScript rule execution, where it's guaranteed that
        //    the `tree_sitter::Tree` exists (because it is owned by the `ddsa_lib::RootContext` on the `bridge::ContextBridge`).
        // 3. We never mutate the `tree_sitter::Tree` or any related nodes.
        unsafe { self.0.to_node() }
    }
}
