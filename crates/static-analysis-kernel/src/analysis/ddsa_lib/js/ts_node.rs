// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::analysis::ddsa_lib::common::{
    load_function, v8_uint, Class, DDSAJsRuntimeError, Instance,
};
use deno_core::v8;
use deno_core::v8::HandleScope;
use std::marker::PhantomData;

/// A deserialized JavaScript object representation of a [`tree_sitter::Node`].
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct TreeSitterNode<T> {
    pub id: u32,
    pub start_line: u32,
    pub start_col: u32,
    pub end_line: u32,
    pub end_col: u32,
    pub node_type_id: u16,
    pub _pd: PhantomData<T>,
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

#[cfg(test)]
mod tests {
    use crate::analysis::ddsa_lib::common::{attach_as_global, v8_interned, Class, Instance};
    use crate::analysis::ddsa_lib::js::{TreeSitterNode, TreeSitterNodeFn};
    use crate::analysis::ddsa_lib::test_utils::{
        cfg_test_runtime, js_class_eq, js_instance_eq, try_execute,
    };
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
        ];
        assert!(js_instance_eq(TreeSitterNodeFn::CLASS_NAME, expected));
        let expected = &[];
        assert!(js_class_eq(TreeSitterNodeFn::CLASS_NAME, expected));
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
}
