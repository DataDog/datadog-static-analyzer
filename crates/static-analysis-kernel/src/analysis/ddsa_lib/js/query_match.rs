// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::analysis;
use crate::analysis::ddsa_lib::common::{
    load_function, swallow_v8_error, v8_interned, Class, DDSAJsRuntimeError, NodeId, StellaCompat,
};
use crate::analysis::ddsa_lib::js::capture::{MultiCaptureTemplate, SingleCaptureTemplate};
use crate::analysis::ddsa_lib::js::TreeSitterNodeFn;
use crate::analysis::ddsa_lib::v8_ds::RustConverter;
use crate::analysis::tree_sitter::TSCaptureContent;
use crate::rust_converter;
use deno_core::v8;
use deno_core::v8::HandleScope;
use std::marker::PhantomData;

/// A function representing the ES6 class `QueryMatch`.
#[derive(Debug)]
pub struct QueryMatch<T> {
    class: v8::Global<v8::Function>,
    single_capture: SingleCaptureTemplate,
    multi_capture: MultiCaptureTemplate,
    /// (See documentation on [`Class`]).
    _pd: PhantomData<T>,
}

rust_converter!(
    (QueryMatch<Class>, analysis::tree_sitter::QueryMatch<NodeId>),
    |&self, scope, value| {
        let values = value
            .iter()
            .map(|tsq_cap| {
                use TSCaptureContent::{Multi, Single};
                let name = tsq_cap.name.as_ref();
                let obj = match &tsq_cap.contents {
                    Single(id) => self.single_capture.new_instance(scope, name, *id),
                    Multi(ids) => self.multi_capture.new_instance(scope, name, ids.as_slice()),
                };
                v8::Local::<v8::Value>::from(obj)
            })
            .collect::<Vec<_>>();
        // Pass `undefined` in if the array is empty to avoid an unnecessary allocation.
        let captures_arg: v8::Local<v8::Value> = if values.is_empty() {
            v8::undefined(scope).into()
        } else {
            v8::Array::new_with_elements(scope, values.as_slice()).into()
        };
        let args = [captures_arg];

        self.class
            .open(scope)
            .new_instance(scope, &args[..])
            .unwrap_or_else(|| swallow_v8_error(|| v8::Object::new(scope)))
            .into()
    }
);
impl QueryMatch<Class> {
    pub const CLASS_NAME: &'static str = "QueryMatch";

    /// Creates a new [`v8::Global`] function by loading [`Self::CLASS_NAME`] from the `scope`.
    pub fn try_new(scope: &mut HandleScope) -> Result<Self, DDSAJsRuntimeError> {
        let class = load_function(scope, Self::CLASS_NAME)?;
        let single_capture = SingleCaptureTemplate::new(scope);
        let multi_capture = MultiCaptureTemplate::new(scope);
        Ok(Self {
            class,
            single_capture,
            multi_capture,
            _pd: PhantomData,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::analysis;
    use crate::analysis::ddsa_lib::common::{v8_interned, v8_uint, NodeId};
    use crate::analysis::ddsa_lib::js::{MultiCaptureTemplate, QueryMatch, SingleCaptureTemplate};
    use crate::analysis::ddsa_lib::test_utils::{
        attach_as_global, cfg_test_v8, js_class_eq, js_instance_eq, make_stub_tsn_bridge,
        try_execute,
    };
    use crate::analysis::ddsa_lib::v8_ds::RustConverter;
    use crate::analysis::tree_sitter::TSQueryCapture;
    use deno_core::v8;
    use deno_core::v8::Handle;
    use std::sync::Arc;

    #[test]
    fn js_properties_canary() {
        let instance_exp = &[
            // Variables
            "_captures",
            // Methods
            "get",
            "getMany",
            "_getId",
            "_getManyIds",
        ];
        assert!(js_instance_eq(QueryMatch::CLASS_NAME, instance_exp));
        let class_expected = &[];
        assert!(js_class_eq(QueryMatch::CLASS_NAME, class_expected));
    }

    /// Tests that a call to `_getId` on a `SingleCapture` properly returns the captured node's id.
    #[test]
    fn get_id_single_on_single() {
        let mut runtime = cfg_test_v8().deno_core_rt();
        let scope = &mut runtime.handle_scope();
        let js_class = QueryMatch::try_new(scope).unwrap();
        let single_cap = TSQueryCapture::<NodeId>::new_single(Arc::<str>::from("cap_name"), 10);
        let captures = vec![single_cap];
        let v8_query_match = js_class.convert_to(scope, &captures);
        attach_as_global(scope, v8_query_match, "QUERY_MATCH");
        let code = r#"QUERY_MATCH._getId("cap_name");"#;
        let res = try_execute(scope, code).unwrap();
        assert_eq!(res.to_rust_string_lossy(scope), "10");

        // A capture name that isn't present should return undefined
        let code = r#"QUERY_MATCH._getId("missing_from_captures");"#;
        let res = try_execute(scope, code).unwrap();
        assert!(res.is_undefined());
    }

    /// Tests that a call to `_getId` on a `MultiCapture` returns the *last* node of the array.
    /// This behavior has been preserved from the original stella library.
    #[test]
    fn get_id_single_on_multi_is_last() {
        let mut runtime = cfg_test_v8().deno_core_rt();
        let scope = &mut runtime.handle_scope();
        let js_class = QueryMatch::try_new(scope).unwrap();
        let multi_cap =
            TSQueryCapture::<NodeId>::new_multi(Arc::<str>::from("cap_name"), vec![10, 20, 30]);
        let captures = vec![multi_cap];
        let v8_query_match = js_class.convert_to(scope, &captures);
        attach_as_global(scope, v8_query_match, "QUERY_MATCH");
        let code = r#"QUERY_MATCH._getId("cap_name");"#;
        let res = try_execute(scope, code).unwrap();
        assert_eq!(res.to_rust_string_lossy(scope), "30");
    }

    /// Tests that a call to `_getManyIds` on a `SingleCapture` returns an array containing only the single node id.
    #[test]
    fn get_many_ids_on_single() {
        let mut runtime = cfg_test_v8().deno_core_rt();
        let scope = &mut runtime.handle_scope();
        let js_class = QueryMatch::try_new(scope).unwrap();
        let single_cap = TSQueryCapture::<NodeId>::new_single(Arc::<str>::from("cap_name"), 10);
        let captures = vec![single_cap];
        let v8_query_match = js_class.convert_to(scope, &captures);
        attach_as_global(scope, v8_query_match, "QUERY_MATCH");

        let code = r#"
const cap_node_ids = QUERY_MATCH._getManyIds("cap_name");
assert(Array.isArray(cap_node_ids), "cap_node_ids had wrong type");
assert(cap_node_ids.length === 1, "array must have exactly one elements");
assert(cap_node_ids[0] === 10, "nodeId was incorrect");
"#;
        let result = try_execute(scope, code).map(|v| v.to_rust_string_lossy(scope));
        assert_eq!(result, Ok("undefined".to_string()));

        // A capture name that isn't present should return undefined
        let code = r#"QUERY_MATCH._getManyIds("missing_from_captures");"#;
        let res = try_execute(scope, code).unwrap();
        assert!(res.is_undefined());
    }

    /// Tests that a call to `_getManyIds` on a `MultiCapture` returns an array of node ids.
    #[test]
    fn get_many_ids_on_multi() {
        let mut runtime = cfg_test_v8().deno_core_rt();
        let scope = &mut runtime.handle_scope();
        let js_class = QueryMatch::try_new(scope).unwrap();
        let multi_cap =
            TSQueryCapture::<NodeId>::new_multi(Arc::<str>::from("cap_name"), vec![10, 20, 30]);
        let captures = vec![multi_cap];
        let v8_query_match = js_class.convert_to(scope, &captures);
        attach_as_global(scope, v8_query_match, "QUERY_MATCH");

        let code = r#"
const cap_node_ids = QUERY_MATCH._getManyIds("cap_name");
assert(Array.isArray(cap_node_ids), "cap_node_ids had wrong type");
assert(cap_node_ids.length === 3, "array must have exactly three elements");
assert(cap_node_ids.join(",") === "10,20,30", "nodeIds were incorrect");
"#;
        let result = try_execute(scope, code).map(|v| v.to_rust_string_lossy(scope));
        assert_eq!(result, Ok("undefined".to_string()));
    }

    /// Tests that a call to `_getManyIds` on a `MultiCapture` that happens to have only a single node id
    /// still returns an array (with a single node id).
    #[test]
    fn get_many_ids_on_multi_with_one_element() {
        let mut runtime = cfg_test_v8().deno_core_rt();
        let scope = &mut runtime.handle_scope();
        let js_class = QueryMatch::try_new(scope).unwrap();
        let multi_cap = TSQueryCapture::<NodeId>::new_multi(Arc::<str>::from("cap_name"), vec![10]);
        let captures = vec![multi_cap];
        let v8_query_match = js_class.convert_to(scope, &captures);
        attach_as_global(scope, v8_query_match, "QUERY_MATCH");

        let code = r#"
const cap_node_ids = QUERY_MATCH._getManyIds("cap_name");
assert(Array.isArray(cap_node_ids), "cap_node_ids had wrong type");
assert(cap_node_ids.length === 1, "array must have exactly one elements");
assert(cap_node_ids[0] === 10, "nodeId was incorrect");
"#;
        let result = try_execute(scope, code).map(|v| v.to_rust_string_lossy(scope));
        assert_eq!(result, Ok("undefined".to_string()));
    }

    /// Tests that the [`RustConverter`] creates a JS class instance with `undefined` passed in as the captures array (`_captures`).
    #[rustfmt::skip]
    #[test]
    fn query_match_converter_empty_undefined() {
        let mut runtime = cfg_test_v8().deno_core_rt();
        let scope = &mut runtime.handle_scope();
        let js_class = QueryMatch::try_new(scope).unwrap();
        let captures = vec![];
        let v8_query_match = js_class.convert_to(scope, &captures);
        let v8_query_match: v8::Local<v8::Object> = v8_query_match.try_into().unwrap();

        let v8_key = v8_interned(scope, "_captures");
        let v8_captures = v8_query_match.open(scope).get(scope, v8_key.into()).unwrap();

        assert!(v8_captures.is_undefined());
    }

    /// Tests that `get` properly retrieves nodes from the `TsNodeBridge`.
    #[test]
    fn get_node() {
        let mut runtime = cfg_test_v8().deno_core_rt();

        let scope = &mut runtime.handle_scope();
        let stub_tsn_bridge = make_stub_tsn_bridge(scope, &[10]);
        attach_as_global(scope, stub_tsn_bridge, "__RUST_BRIDGE__ts_node");

        let js_class = QueryMatch::try_new(scope).unwrap();
        let single_cap = TSQueryCapture::<NodeId>::new_single(Arc::<str>::from("cap_name"), 10);
        let captures = vec![single_cap];
        let v8_query_match = js_class.convert_to(scope, &captures);
        attach_as_global(scope, v8_query_match, "QUERY_MATCH");

        let code = r#"assert(QUERY_MATCH.get("cap_name").id === 10);"#;
        let result = try_execute(scope, code).map(|v| v.to_rust_string_lossy(scope));
        assert_eq!(result, Ok("undefined".to_string()));
    }

    /// Tests that `getMany` properly retrieves nodes from the `TsNodeBridge`.
    #[test]
    fn get_many_nodes() {
        let mut runtime = cfg_test_v8().deno_core_rt();

        let scope = &mut runtime.handle_scope();
        let stub_tsn_bridge = make_stub_tsn_bridge(scope, &[10, 20]);
        attach_as_global(scope, stub_tsn_bridge, "__RUST_BRIDGE__ts_node");

        let js_class = QueryMatch::try_new(scope).unwrap();
        let multi_cap =
            TSQueryCapture::<NodeId>::new_multi(Arc::<str>::from("cap_name"), vec![10, 20]);
        let captures = vec![multi_cap];
        let v8_query_match = js_class.convert_to(scope, &captures);
        attach_as_global(scope, v8_query_match, "QUERY_MATCH");

        let code = r#"
const stubNodes = QUERY_MATCH.getMany("cap_name");
assert(stubNodes.length === 2);
assert(stubNodes[0].id === 10);
assert(stubNodes[1].id === 20);
"#;
        let result = try_execute(scope, code).map(|v| v.to_rust_string_lossy(scope));
        assert_eq!(result, Ok("undefined".to_string()));
    }
}
