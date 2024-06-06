// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::analysis::ddsa_lib::common::NodeId;
use crate::analysis::ddsa_lib::{bridge, runtime};
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
    let ts_node = restore_ts_node_for_op(&node_bridge, node_id)?;
    tree_text
        .get(ts_node.start_byte()..ts_node.end_byte())
        .map(ToString::to_string)
}

/// A function that restores a `tree_sitter::Node` given its `NodeId`.
fn restore_ts_node_for_op(
    bridge: &bridge::TsNodeBridge,
    node_id: NodeId,
) -> Option<tree_sitter::Node> {
    bridge.get_raw(node_id).map(|raw_node| {
        // Safety:
        // 1. An op will only be called during a JavaScript rule execution, where it's guaranteed that
        //    the `tree_sitter::Tree` exists (and is owned by the `ddsa_lib::RootContext` on the `bridge::ContextBridge`).
        // 2. We never mutate the `tree_sitter::Tree` or any related nodes.
        // 3. While the `node_id` can be modified by a JavaScript rule, only Rust can insert RawTSNode data
        //    into the bridge, so there is no risk of user data flowing into this unsafe block.
        unsafe { raw_node.to_node() }
    })
}
