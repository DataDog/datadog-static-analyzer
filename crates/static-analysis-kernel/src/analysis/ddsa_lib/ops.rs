// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::analysis::ddsa_lib::common::{v8_uint, NodeId};
use crate::analysis::ddsa_lib::{bridge, runtime, RawTSNode};
use deno_core::{op2, v8, OpState};
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

/// Given a tree-sitter node (via its `node_id`), this function traverses the tree to find the
/// named children of the node, inserting them into the `TsNodeBridge`.
///
/// Nodes are returned as a `v8::Uint32Array` of tuples: (NodeId, FieldId):
/// ```text
/// |             Node A              |             Node B              |
/// |    NodeId A    |    FieldId A   |    NodeId B    |    FieldId B   |
///  ________________ ________________ ________________ ________________
/// |                |                |                |                |
/// 0                1                2                3
///      32 bits          32 bits          32 bits          32 bits
/// ```
/// A NodeId is always at an even index. Its corresponding FieldId is always at the (n + 1) index.
/// If there is no FieldId, the uint32 will be 0.
///
/// If the node doesn't exist, or it has no named children, `None` is returned.
#[op2]
pub fn op_ts_node_named_children<'s>(
    state: &OpState,
    scope: &mut v8::HandleScope<'s>,
    #[smi] node_id: u32,
) -> Option<v8::Local<'s, v8::Uint32Array>> {
    let ts_node_bridge = state.borrow::<Rc<RefCell<bridge::TsNodeBridge>>>();

    let safe_raw_ts_node = OpSafeRawTSNode::try_new(&ts_node_bridge.borrow(), node_id)?;
    let ts_node = safe_raw_ts_node.to_node();

    let count = ts_node.named_child_count();
    if count == 0 {
        None
    } else {
        let ids_buf = v8::ArrayBuffer::new(scope, 4 * count * 2);
        let uint_array = v8::Uint32Array::new(scope, ids_buf, 0, count * 2)
            .expect("v8 Uint32Array should be able to be created");
        let mut bridge_ref = ts_node_bridge.borrow_mut();

        let mut cursor = ts_node.walk();
        // This logic is extracted from `tree_sitter::Node::named_children`. We don't use the function
        // directly because of the way its API mutably borrows the cursor, which would prevent us from
        // inspecting values like the cursor's current field_id.
        cursor.goto_first_child();
        for i in 0..count {
            while !cursor.node().is_named() {
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
            let child_node = cursor.node();

            let nid = bridge_ref.insert(scope, child_node);
            let nid = v8_uint(scope, nid);
            let nid_index = i * 2;
            uint_array.set_index(scope, nid_index as u32, nid.into());
            // The array buffer is zero-initialized, so we only have to write the field_id if it exists.
            if let Some(fid) = cursor.field_id() {
                let fid = v8_uint(scope, fid.get() as u32);
                uint_array.set_index(scope, (nid_index + 1) as u32, fid.into());
            }

            cursor.goto_next_sibling();
        }

        Some(uint_array)
    }
}

/// An op to test the [`deno_core::op2`] macro's serialization of `Option`.
///
/// Returns `Some(123)` if `true` is passed in, or `None` if `false` is passed in.
//  Note: Due to the op2 macro implementation, we can't mark this `[cfg(test)]`
#[op2]
pub(crate) fn cfg_test_op_rust_option(return_some: bool) -> Option<u32> {
    return_some.then_some(123)
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

#[cfg(test)]
mod tests {
    use crate::analysis::ddsa_lib::test_utils::{cfg_test_runtime, try_execute};

    /// A [`deno_core::op2`] should serialize [`Option::None`] to [`v8::null`], not [`v8::undefined`].
    /// This test is mostly for explicit documentation, as we don't expect any upstream changes to this.
    #[test]
    fn none_serialization_to_null() {
        let mut rt = cfg_test_runtime();
        let scope = &mut rt.handle_scope();
        let res = try_execute(scope, "Deno.core.ops.cfg_test_op_rust_option(true);").unwrap();
        assert_eq!(res.uint32_value(scope).unwrap(), 123);

        let res = try_execute(scope, "Deno.core.ops.cfg_test_op_rust_option(false);").unwrap();
        assert!(res.is_null());
        assert!(!res.is_undefined());
    }
}
