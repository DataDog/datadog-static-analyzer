// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::analysis::ddsa_lib::bridge::ts_node::TsNodeBridge;
use crate::analysis::ddsa_lib::common::{Class, DDSAJsRuntimeError, NodeId};
use crate::analysis::ddsa_lib::js;
use crate::analysis::ddsa_lib::v8_ds::MirroredVec;
use crate::analysis::tree_sitter::QueryMatch;
use deno_core::v8;
use deno_core::v8::HandleScope;

/// A stateful bridge holding a collection of [`QueryMatch<NodeId>`].
pub struct QueryMatchBridge(MirroredVec<QueryMatch<NodeId>, js::QueryMatch<Class>>);

impl QueryMatchBridge {
    /// Constructs a new `QueryMatchBridge` for the given `scope`. The scope's [`v8::Context::global`] must
    /// have class functions with the following identifiers:
    /// * [`js::QueryMatch::CLASS_NAME`]
    pub fn try_new(scope: &mut HandleScope) -> Result<Self, DDSAJsRuntimeError> {
        /// The `QueryMatchBridge` persists across the entire lifetime of the [`JsRuntime`](use crate::analysis::ddsa_lib::JsRuntime),
        /// so push operations amortize to O(1) (because we aren't constantly re-creating this vec).
        ///
        /// Even so, we allocate an (arbitrary non-zero) initial capacity, as we know all executions will contain query matches.
        const CAPACITY: u32 = 16;

        let js_class = js::QueryMatch::try_new(scope)?;
        Ok(Self(MirroredVec::with_capacity(js_class, scope, CAPACITY)))
    }

    /// Sets the bridge's data to the list of [`QueryMatch`]es, inserting tree-sitter nodes
    /// into the provided `TsNodeBridge`.
    ///
    /// NOTE: if the bridge had existing `QueryMatch`es, the tree-sitter nodes associated with them
    ///       will not be removed from the `TsNodeBridge`.
    pub fn set_data<'tree>(
        &mut self,
        scope: &mut HandleScope,
        matches: impl Into<Vec<QueryMatch<tree_sitter::Node<'tree>>>>,
        node_bridge: &mut TsNodeBridge,
    ) {
        let matches = matches.into();
        // Pass each node in via the bridge (assigning it an id), and use this id to transform
        // the `QueryMatch` into `QueryMatch<NodeId>`.
        let q_matches = matches
            .into_iter()
            .map(|q_match| {
                q_match
                    .into_iter()
                    .map(|capture| node_bridge.insert_capture(scope, capture))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        self.0.set_data(scope, q_matches)
    }

    /// Returns the number of `QueryMatch`es in the bridge.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true if the bridge is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns a local handle to the underlying [`v8::Global`] array.
    pub fn as_local<'s>(&self, scope: &mut HandleScope<'s>) -> v8::Local<'s, v8::Array> {
        self.0.as_local(scope)
    }
}

#[cfg(test)]
mod tests {
    use crate::analysis::ddsa_lib::bridge::query_match::QueryMatchBridge;
    use crate::analysis::ddsa_lib::bridge::ts_node::TsNodeBridge;
    use crate::analysis::ddsa_lib::common::NodeId;
    use crate::analysis::ddsa_lib::test_utils::cfg_test_runtime;
    use crate::analysis::tree_sitter::{get_tree, TSCaptureContent, TSQuery};
    use crate::model::common::Language;
    use deno_core::JsRuntime;

    fn setup_bridge() -> (JsRuntime, QueryMatchBridge, TsNodeBridge) {
        let mut runtime = cfg_test_runtime();
        let qm_bridge = QueryMatchBridge::try_new(&mut runtime.handle_scope()).unwrap();
        let tsn_bridge = TsNodeBridge::try_new(&mut runtime.handle_scope()).unwrap();
        (runtime, qm_bridge, tsn_bridge)
    }

    /// Query matches should be synced between Rust, and nodes should be inserted into the tree-sitter node bridge.
    #[test]
    fn query_matches_set_multiple() {
        let (mut runtime, mut query_match_bridge, mut ts_node_bridge) = setup_bridge();
        fn get_node_id_at_idx(bridge: &QueryMatchBridge, idx: usize) -> NodeId {
            let value = bridge.0.get(idx).unwrap();
            let TSCaptureContent::Single(node_id) = value[0].contents else {
                unreachable!("this is a single capture");
            };
            node_id
        }

        let scope = &mut runtime.handle_scope();

        let text = "\
const abc = calc(12, 34, 56);
const def = calc(78, 90);
const ghi = 'hello' + ' world';
";
        let tree = get_tree(text, &Language::JavaScript).unwrap();
        let query = "\
(variable_declarator
  name: (identifier) @name
)
";
        let query = TSQuery::try_new(&tree.language(), query).unwrap();
        let matches = query
            .cursor()
            .matches(tree.root_node(), text)
            .collect::<Vec<_>>();
        assert!(query_match_bridge.is_empty());
        assert!(ts_node_bridge.is_empty());
        query_match_bridge.set_data(scope, matches.clone(), &mut ts_node_bridge);
        assert_eq!(query_match_bridge.len(), 3);
        assert_eq!(ts_node_bridge.len(), 3);

        for idx in 0..=2 {
            // Get the NodeId in the `qm_bridge`.
            let node_id = get_node_id_at_idx(&query_match_bridge, idx);
            // Ensure it is present in the `tsn_bridge`.
            assert!(ts_node_bridge.get_raw(node_id).is_some());
        }

        // The `QueryMatchBridge` doesn't clear nodes from `TsNodeBridge` when values change.
        query_match_bridge.set_data(scope, &matches[0..2], &mut ts_node_bridge);
        assert_eq!(query_match_bridge.len(), 2);
        assert_eq!(ts_node_bridge.len(), 3);
        let text = "\
// Arbitrary JavaScript that contains `identifier` CST nodes
const alpha = 'bravo';
";
        let tree = get_tree(text, &Language::JavaScript).unwrap();
        let matches = query
            .cursor()
            .matches(tree.root_node(), text)
            .collect::<Vec<_>>();
        query_match_bridge.set_data(scope, matches, &mut ts_node_bridge);
        assert_eq!(get_node_id_at_idx(&query_match_bridge, 0), 3);
        assert_eq!(ts_node_bridge.len(), 4);
    }
}
