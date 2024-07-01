// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::analysis::ddsa_lib::common::{
    load_function, v8_uint, Class, DDSAJsRuntimeError, Instance, NodeId,
};
use deno_core::v8;
use deno_core::v8::HandleScope;
use std::marker::PhantomData;

/// A deserialized JavaScript object representation of a [`tree_sitter::Node`].
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct TreeSitterNode<T> {
    id: u32,
    start_line: u32,
    start_col: u32,
    end_line: u32,
    end_col: u32,
    /// The type of node this is. This corresponds to [`tree_sitter::Node::kind_id`].
    node_type_id: u16,
    _pd: PhantomData<T>,
}

impl<T> TreeSitterNode<T> {
    /// Converts the provided [`tree_sitter::Node`] into a `TreeSitterNode`, assigning the provided id.
    pub fn from_ts_node(id: NodeId, node: tree_sitter::Node) -> Self {
        // NOTE: We normalize the 0-based `tree_sitter::Point` to be 1-based.
        fn normalize_ts_point_num(num: usize) -> u32 {
            num as u32 + 1
        }
        let tree_sitter::Point {
            row: start_line,
            column: start_col,
        } = node.start_position();
        let tree_sitter::Point {
            row: end_line,
            column: end_col,
        } = node.end_position();
        Self {
            id,
            start_line: normalize_ts_point_num(start_line),
            start_col: normalize_ts_point_num(start_col),
            end_line: normalize_ts_point_num(end_line),
            end_col: normalize_ts_point_num(end_col),
            node_type_id: node.kind_id(),
            _pd: PhantomData,
        }
    }
}

/// A function representing the ES6 class `TreeSitterNode`.
#[derive(Debug)]
pub struct TreeSitterNodeFn<T>(v8::Global<v8::Function>, PhantomData<T>);

impl TreeSitterNodeFn<Class> {
    pub const CLASS_NAME: &'static str = "TreeSitterNode";

    /// Creates a new [`v8::Global`] function by loading [`Self::CLASS_NAME`] from the `scope`.
    pub fn try_new(scope: &mut HandleScope) -> Result<Self, DDSAJsRuntimeError> {
        load_function(scope, Self::CLASS_NAME).map(|func| Self(func, PhantomData))
    }

    /// Creates a new instance of the `TreeSitterNode` class.
    pub fn new_instance<'s>(
        &self,
        scope: &mut HandleScope<'s>,
        ts_node: TreeSitterNode<Instance>,
    ) -> v8::Local<'s, v8::Object> {
        let id = v8_uint(scope, ts_node.id).into();
        let start_line = v8_uint(scope, ts_node.start_line).into();
        let start_col = v8_uint(scope, ts_node.start_col).into();
        let end_line = v8_uint(scope, ts_node.end_line).into();
        let end_col = v8_uint(scope, ts_node.end_col).into();
        let node_type_id = v8_uint(scope, ts_node.node_type_id as u32).into();
        let args = [id, start_line, start_col, end_line, end_col, node_type_id];
        self.0
            .open(scope)
            .new_instance(scope, &args[..])
            .expect("class constructor should not throw")
    }
}

/// The name of the ES6 class that wraps a `TreeSitterNode`, providing additional metadata about
/// the node as a child of another node.
///
/// This is only constructed in JavaScript, so we only track the name here.
const FIELD_CHILD_NODE_CLASS_NAME: &str = "TreeSitterFieldChildNode";

#[cfg(test)]
mod tests {
    use crate::analysis::ddsa_lib::common::{v8_interned, v8_string, Class, Instance};
    use crate::analysis::ddsa_lib::context::ts_lang;
    use crate::analysis::ddsa_lib::js::ts_node::FIELD_CHILD_NODE_CLASS_NAME;
    use crate::analysis::ddsa_lib::js::{TreeSitterNode, TreeSitterNodeFn};
    use crate::analysis::ddsa_lib::test_utils::{
        attach_as_global, cfg_test_runtime, js_class_eq, js_instance_eq, make_stub_root_context,
        try_execute,
    };
    use crate::analysis::tree_sitter::get_tree_sitter_language;
    use crate::model::common::Language;
    use deno_core::v8;
    use std::marker::PhantomData;

    #[test]
    fn js_properties_canary() {
        let expected = &[
            // Variables
            "id",
            "_startLine",
            "_startCol",
            "_endLine",
            "_endCol",
            "_typeId",
            "_cachedStart",
            "_cachedEnd",
            "__js_cachedText",
            // Methods
            "text",
            "type",
            "start",
            "end",
            "children",
        ];
        assert!(js_instance_eq(TreeSitterNodeFn::CLASS_NAME, expected));
        let expected = &[];
        assert!(js_class_eq(TreeSitterNodeFn::CLASS_NAME, expected));

        let expected = &[
            // Variables
            "_fieldId",
            // Methods
            "fieldName",
        ];
        assert!(js_instance_eq(FIELD_CHILD_NODE_CLASS_NAME, expected));
        let expected = &[];
        assert!(js_class_eq(FIELD_CHILD_NODE_CLASS_NAME, expected));
    }

    /// Tests that the line and column number of the node is 1-based. This test is necessary because
    /// [`tree_sitter::Point`] is 0-based, whereas we use a 1-based number.
    #[test]
    fn ts_node_line_col_one_based() {
        let lang = get_tree_sitter_language(&Language::JavaScript);
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&lang).unwrap();

        let tree = parser.parse(r#"foo(bar, baz);"#, None).unwrap();
        let root = tree.root_node();

        assert_eq!(root.start_position().row, 0);
        assert_eq!(root.start_position().column, 0);
        assert_eq!(root.end_position().row, 0);
        assert_eq!(root.end_position().column, 14);

        let tree_sitter_node = TreeSitterNode::<Instance>::from_ts_node(0, root);

        assert_eq!(tree_sitter_node.start_line, 1);
        assert_eq!(tree_sitter_node.start_col, 1);
        assert_eq!(tree_sitter_node.end_line, 1);
        assert_eq!(tree_sitter_node.end_col, 15);
    }

    /// Tests that we use the [`tree_sitter::Node::kind_id`] instead of the [`tree_sitter::Node::grammar_id`], which
    /// has subtle differences.
    #[rustfmt::skip]
    #[test]
    fn ts_node_kind_id() {
        let lang = get_tree_sitter_language(&Language::JavaScript);
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&lang).unwrap();

        let text = r#"{ keyName: "value" }"#;
        let tree = parser.parse(text, None).unwrap();

        let query = tree_sitter::Query::new(&lang, "(pair key: (_) @cap)").unwrap();
        let mut cursor = tree_sitter::QueryCursor::new();
        let ts_node = cursor.matches(&query, tree.root_node(), text.as_bytes()).next().unwrap().captures.first().unwrap().node;
        // First make sure this test is properly constructed (an upstream tree_sitter grammar change
        // may invalidate this, so we need to confirm).
        // This should resolve to `assert_ne!("identifier", "property_identifier")`
        assert_ne!(ts_node.grammar_name(), ts_node.kind());

        let tree_sitter_node = TreeSitterNode::<Instance>::from_ts_node(0, ts_node);
        assert_eq!(tree_sitter_node.node_type_id, ts_node.kind_id());
    }

    /// Tests that the getter for `start` and `end` is lazily instantiated and returned.
    #[test]
    fn position_getters() {
        let mut runtime = cfg_test_runtime();
        let scope = &mut runtime.handle_scope();
        let js_class = TreeSitterNodeFn::<Class>::try_new(scope).unwrap();

        let base_ts_node = TreeSitterNode::<Instance> {
            id: 3,
            start_line: 123,
            start_col: 1,
            end_line: 456,
            end_col: 32,
            node_type_id: 8,
            _pd: PhantomData,
        };
        let v8_ts_node = js_class.new_instance(scope, base_ts_node);
        attach_as_global(scope, v8_ts_node, "TS_NODE");

        for (getter, cache_name, (expected_line, expected_col)) in [
            ("start", "_cachedStart", (123, 1)),
            ("end", "_cachedEnd", (456, 32)),
        ] {
            // Verify the cache behavior
            let s_cache_name = v8_interned(scope, cache_name);
            let v8_cached_pos = v8_ts_node.get(scope, s_cache_name.into()).unwrap();
            assert!(v8_cached_pos.is_undefined());

            // Return the value from the provided getter: e.g. `TS_NODE.start`.
            let code = format!("TS_NODE.{};", getter);
            let res = try_execute(scope, &code).unwrap();

            // Ensure we get a position object back
            let v8_returned_pos: v8::Local<v8::Object> = res.try_into().unwrap();
            let own_props = v8_returned_pos
                .get_own_property_names(scope, Default::default())
                .unwrap();
            assert_eq!(own_props.length(), 2);

            let s_line = v8_interned(scope, "line");
            let s_col = v8_interned(scope, "col");
            let v8_line = v8_returned_pos.get(scope, s_line.into()).unwrap();
            let v8_col = v8_returned_pos.get(scope, s_col.into()).unwrap();
            assert_eq!(v8_line.uint32_value(scope).unwrap(), expected_line);
            assert_eq!(v8_col.uint32_value(scope).unwrap(), expected_col);

            // Assert that node cached this position (i.e. the property is no longer undefined).
            let v8_cached_pos = v8_ts_node.get(scope, s_cache_name.into()).unwrap();
            assert!(v8_cached_pos.is_object());

            // And then assert that beyond just property value equality, the getter returns the
            // exact same object as the cached object.
            assert_eq!(v8_cached_pos.get_hash(), v8_returned_pos.get_hash())
        }
    }

    /// Tests that the `type` getter returns the node type as a name string.
    #[test]
    fn type_getter() {
        let mut runtime = cfg_test_runtime();
        let scope = &mut runtime.handle_scope();
        let js_class = TreeSitterNodeFn::<Class>::try_new(scope).unwrap();

        let lang_js = get_tree_sitter_language(&Language::JavaScript);
        // (Included to alert if tree_sitter grammar changes the node kind ids)
        const EXPECTED: (u16, &str) = (149, "variable_declarator");
        assert_eq!(lang_js.node_kind_for_id(EXPECTED.0), Some(EXPECTED.1));

        let stub_root_ctx = make_stub_root_context(scope, &[], "", "", Some(&lang_js));
        attach_as_global(scope, stub_root_ctx, "__RUST_BRIDGE__context");

        let base_ts_node = TreeSitterNode::<Instance> {
            id: 2,
            start_line: 456,
            start_col: 5,
            end_line: 456,
            end_col: 32,
            node_type_id: EXPECTED.0,
            _pd: PhantomData,
        };
        let v8_ts_node = js_class.new_instance(scope, base_ts_node);
        attach_as_global(scope, v8_ts_node, "TS_NODE");

        let code = "TS_NODE.type;";
        let ret_value = try_execute(scope, code).unwrap();
        assert_eq!(ret_value.to_rust_string_lossy(scope), EXPECTED.1);

        // And if the TSNode is mutated to have an invalid _typeId, it should return an empty string.
        let code = "TS_NODE._typeId = 99999; TS_NODE.type;";
        let ret_value = try_execute(scope, code).unwrap();
        assert_eq!(ret_value.to_rust_string_lossy(scope), "");
    }

    /// Tests that a [`FIELD_CHILD_NODE_CLASS_NAME`] wraps a [`TreeSitterNodeFn::CLASS_NAME`] with additional metadata,
    /// but that it provides all the same properties as the node itself.
    #[test]
    fn field_child_interface() {
        let mut runtime = cfg_test_runtime();
        let scope = &mut runtime.handle_scope();
        let js_class = TreeSitterNodeFn::<Class>::try_new(scope).unwrap();

        let lang_js = get_tree_sitter_language(&Language::JavaScript);
        // (Assertion included to alert if upstream tree-sitter grammar unexpectedly alters metadata)
        assert_eq!(lang_js.field_name_for_id(30), Some("optional_chain"));

        let base_ts_node = TreeSitterNode::<Instance> {
            id: 2,
            start_line: 1,
            start_col: 5,
            end_line: 1,
            end_col: 12,
            node_type_id: 0, // Unused
            _pd: PhantomData,
        };
        let v8_ts_node = js_class.new_instance(scope, base_ts_node);
        attach_as_global(scope, v8_ts_node, "TS_NODE");

        // We test the prototype, and then ensure properties and getters have the correct "this" context.
        let code = r#"
const assert = (val, msg) => { if (!val) throw new Error(msg); };

const child = new TreeSitterFieldChildNode(TS_NODE, 30);
assert(child instanceof TreeSitterNode, "should be a TreeSitterNode instance");
assert(child instanceof TreeSitterFieldChildNode, "should (also) be a TreeSitterFieldChildNode");
assert(child._startLine === 1, "_startLine value incorrect");
assert(child._startCol === 5, "_startCol value incorrect");
assert(child.start.col === 5, "start getter value incorrect");
assert(child._fieldId === 30, "_fieldId value incorrect");
123;
"#;
        let res = try_execute(scope, code).unwrap();
        assert!(res.is_uint32() && res.uint32_value(scope).unwrap() == 123);
    }
}
