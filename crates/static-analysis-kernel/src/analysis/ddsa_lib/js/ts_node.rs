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
    use crate::analysis::ddsa_lib::js::TreeSitterNodeFn;
    use crate::analysis::ddsa_lib::test_utils::{js_class_eq, js_instance_eq};

    #[test]
    fn js_properties_canary() {
        let expected = &[
            // Variables
            "id",
            "startLine",
            "startCol",
            "endLine",
            "endCol",
            "_typeId",
            "__js_cachedText",
            // Methods
            "text",
            "type",
        ];
        assert!(js_instance_eq(TreeSitterNodeFn::CLASS_NAME, expected));
        let expected = &[];
        assert!(js_class_eq(TreeSitterNodeFn::CLASS_NAME, expected));
    }
}
