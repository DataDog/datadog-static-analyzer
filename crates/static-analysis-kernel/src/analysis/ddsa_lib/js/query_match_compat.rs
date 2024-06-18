// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::analysis::ddsa_lib::common::{
    load_function, Class, DDSAJsRuntimeError, NodeId, StellaCompat,
};
use crate::analysis::ddsa_lib::js::QueryMatch;
use crate::analysis::ddsa_lib::v8_ds::RustConverter;
use crate::{analysis, rust_converter};
use deno_core::v8;
use deno_core::v8::HandleScope;
use std::marker::PhantomData;
rust_converter!(
    (
        QueryMatchCompat<Class>,
        StellaCompat<analysis::tree_sitter::QueryMatch<NodeId>>
    ),
    |&self, scope, value| {
        let qm_rust_converter: &dyn RustConverter<
            Item = analysis::tree_sitter::QueryMatch<NodeId>,
        > = &self.proxied;
        let query_match_instance = qm_rust_converter.convert_to(scope, value);

        // Then pass the `QueryMatch` instance into the `QueryMatchCompat` constructor to build a compat instance.
        let args = [query_match_instance];
        self.class
            .open(scope)
            .new_instance(scope, &args[..])
            .expect("class constructor should not throw")
            .into()
    }
);

/// A function representing the ES6 class `QueryMatchCompat`.
#[derive(Debug)]
pub struct QueryMatchCompat<T> {
    /// The `QueryMatchCompat` class.
    class: v8::Global<v8::Function>,
    /// The `QueryMatch` class. An instance of this is used as a JavaScript `Proxy` target.
    proxied: QueryMatch<T>,
    _pd: PhantomData<T>,
}

impl QueryMatchCompat<Class> {
    pub const CLASS_NAME: &'static str = "QueryMatchCompat";

    /// Creates a new [`v8::Global`] function by loading [`Self::CLASS_NAME`] and instantiating
    /// a [`QueryMatch<T>`].
    pub fn try_new(scope: &mut HandleScope) -> Result<Self, DDSAJsRuntimeError> {
        let class = load_function(scope, Self::CLASS_NAME)?;
        let proxied = QueryMatch::<Class>::try_new(scope)?;
        Ok(Self {
            class,
            proxied,
            _pd: PhantomData,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::analysis::ddsa_lib::common::{v8_interned, NodeId};
    use crate::analysis::ddsa_lib::js::query_match_compat::QueryMatchCompat;
    use crate::analysis::ddsa_lib::test_utils::{
        attach_as_global, cfg_test_runtime, js_class_eq, js_instance_eq, make_stub_tsn_bridge,
        try_execute,
    };
    use crate::analysis::ddsa_lib::v8_ds::RustConverter;
    use crate::analysis::tree_sitter::TSQueryCapture;
    use deno_core::v8;
    use std::sync::Arc;

    /// Sample contents of a file to test the compatibility layer
    const COMPAT_FILE_CONTENTS: &str = "\
const abc = 123; thisStringRepresents(\"File Contents\");\
";
    /// Sample filename to test the compatibility layer
    const COMPAT_FILENAME: &str = "filename.js";

    /// Creates a stub [`v8::Object`] that represents a `RootContext`.
    fn make_stub_root_context<'s>(
        scope: &mut v8::HandleScope<'s>,
        arguments: &[(&str, &str)],
    ) -> v8::Local<'s, v8::Object> {
        use crate::analysis::ddsa_lib::common::{load_function, v8_string};

        let v8_root_ctx = v8::Object::new(scope);

        let rule_ctx_class = load_function(scope, "RuleContext").unwrap();
        let rule_ctx_class = rule_ctx_class.open(scope);
        let v8_arguments = v8::Map::new(scope);
        for &(name, value) in arguments {
            let s_key = v8_interned(scope, name);
            let v8_value = v8_string(scope, value);
            v8_arguments.set(scope, s_key.into(), v8_value.into());
        }
        let v8_rule_ctx = rule_ctx_class
            .new_instance(scope, &[v8_arguments.into()][..])
            .unwrap();

        let s_key_rule_ctx = v8_interned(scope, "ruleCtx");
        v8_root_ctx.set(scope, s_key_rule_ctx.into(), v8_rule_ctx.into());

        let s_key_filename = v8_interned(scope, "filename");
        let v8_filename = v8_string(scope, COMPAT_FILENAME);
        v8_root_ctx.set(scope, s_key_filename.into(), v8_filename.into());

        let s_key_file_contents = v8_interned(scope, "fileContents");
        let v8_file_contents = v8_string(scope, COMPAT_FILE_CONTENTS);
        v8_root_ctx.set(scope, s_key_file_contents.into(), v8_file_contents.into());

        v8_root_ctx
    }

    #[test]
    fn js_properties_canary() {
        // The class is a thin wrapper around a Proxy, so there are no native instance properties.
        let instance_exp = &[];
        assert!(js_instance_eq(QueryMatchCompat::CLASS_NAME, instance_exp));
        let class_expected = &[];
        assert!(js_class_eq(QueryMatchCompat::CLASS_NAME, class_expected));
    }

    /// Tests the interface for `<QueryMatchCompat>.captures`.
    #[test]
    fn compat_layer_captures() {
        let mut runtime = cfg_test_runtime();

        let scope = &mut runtime.handle_scope();
        let stub_tsn_bridge = make_stub_tsn_bridge(scope, &[10]);
        attach_as_global(scope, stub_tsn_bridge, "__RUST_BRIDGE__ts_node");

        let js_class = QueryMatchCompat::try_new(scope).unwrap();
        let single_cap = TSQueryCapture::<NodeId>::new_single(Arc::<str>::from("cap_name"), 10);
        let captures = vec![single_cap];
        let v8_query_match_compat = js_class.convert_to(scope, &captures.into());
        attach_as_global(scope, v8_query_match_compat, "QUERY_MATCH");

        let code = r#"
const assert = (val, msg) => { if (!val) throw new Error(msg); };
assert(QUERY_MATCH.captures["cap_name"].id === 10);
assert(QUERY_MATCH.captures.cap_name.id === 10);
"#;
        let result = try_execute(scope, code).map(|v| v.to_rust_string_lossy(scope));
        assert_eq!(result, Ok("undefined".to_string()));
    }

    /// Tests the edge case in `QueryMatchCompat` where a capture name collides with a `QueryMatch` instance method.
    #[test]
    fn compat_layer_captures_name_collision() {
        let mut runtime = cfg_test_runtime();

        let scope = &mut runtime.handle_scope();
        let stub_tsn_bridge = make_stub_tsn_bridge(scope, &[10, 20]);
        attach_as_global(scope, stub_tsn_bridge, "__RUST_BRIDGE__ts_node");

        let js_class = QueryMatchCompat::try_new(scope).unwrap();
        let single_cap = TSQueryCapture::<NodeId>::new_single(Arc::<str>::from("cap_name"), 10);
        let get_cap = TSQueryCapture::<NodeId>::new_single(Arc::<str>::from("get"), 20);
        let captures = vec![single_cap, get_cap];
        let v8_query_match_compat = js_class.convert_to(scope, &captures.into());
        attach_as_global(scope, v8_query_match_compat, "QUERY_MATCH");

        let code = r#"
const assert = (val, msg) => { if (!val) throw new Error(msg); };
assert(QUERY_MATCH.captures["get"].id === 20);
assert(QUERY_MATCH.captures.get.id === 20);
"#;
        let result = try_execute(scope, code).map(|v| v.to_rust_string_lossy(scope));
        assert_eq!(result, Ok("undefined".to_string()));

        for method in ["get", "getMany", "_getId", "_getManyIds"] {
            let code = format!(
                "\
assert(QUERY_MATCH.captures.cap_name.id === 10);
QUERY_MATCH.captures.{}(\"cap_name\");",
                method
            );
            let result = try_execute(scope, &code).map(|v| v.to_rust_string_lossy(scope));
            let expected_msg = format!(
                "TypeError: QUERY_MATCH.captures.{} is not a function",
                method
            );
            assert_eq!(result, Err(expected_msg));
        }
    }

    /// Tests the interface for `<QueryMatchCompat>.capturesList`.
    #[test]
    fn compat_layer_captures_list() {
        let mut runtime = cfg_test_runtime();

        let scope = &mut runtime.handle_scope();
        let stub_tsn_bridge = make_stub_tsn_bridge(scope, &[10, 20]);
        attach_as_global(scope, stub_tsn_bridge, "__RUST_BRIDGE__ts_node");

        let js_class = QueryMatchCompat::try_new(scope).unwrap();
        let multi_cap =
            TSQueryCapture::<NodeId>::new_multi(Arc::<str>::from("cap_name"), vec![10, 20]);
        let captures = vec![multi_cap];
        let v8_query_match_compat = js_class.convert_to(scope, &captures.into());
        attach_as_global(scope, v8_query_match_compat, "QUERY_MATCH");

        let code = r#"
const assert = (val, msg) => { if (!val) throw new Error(msg); };
const stubNodes = QUERY_MATCH.capturesList["cap_name"];
assert(stubNodes.length === 2);
assert(stubNodes[0].id === 10);
assert(stubNodes[1].id === 20);
"#;
        let result = try_execute(scope, code).map(|v| v.to_rust_string_lossy(scope));
        assert_eq!(result, Ok("undefined".to_string()));
    }

    /// `QueryMatch` returns `undefined` for an empty capture list. `<QueryMatchCompat>.capturesList` should return an empty array.
    #[test]
    fn compat_layer_captures_list_empty() {
        let mut runtime = cfg_test_runtime();

        let scope = &mut runtime.handle_scope();
        let stub_tsn_bridge = make_stub_tsn_bridge(scope, &[]);
        attach_as_global(scope, stub_tsn_bridge, "__RUST_BRIDGE__ts_node");

        let js_class = QueryMatchCompat::try_new(scope).unwrap();
        let captures = vec![];
        let v8_query_match_compat = js_class.convert_to(scope, &captures.into());
        attach_as_global(scope, v8_query_match_compat, "QUERY_MATCH");

        let code = r#"
const assert = (val, msg) => { if (!val) throw new Error(msg); };
const stubNodes = QUERY_MATCH.capturesList["cap_name"];
assert(Array.isArray(stubNodes) && stubNodes.length === 0);
"#;
        let result = try_execute(scope, code).map(|v| v.to_rust_string_lossy(scope));
        assert_eq!(result, Ok("undefined".to_string()));
    }

    /// Tests the interface for `<QueryMatchCompat>.context`
    #[rustfmt::skip]
    #[test]
    fn compat_layer_context() {
        let mut runtime = cfg_test_runtime();

        let scope = &mut runtime.handle_scope();
        let stub_root_context = make_stub_root_context(scope, &[("arg_name1", "123")]);
        attach_as_global(scope, stub_root_context, "__RUST_BRIDGE__context");

        let js_class = QueryMatchCompat::try_new(scope).unwrap();
        let captures = vec![];
        let v8_query_match_compat = js_class.convert_to(scope, &captures.into());
        attach_as_global(scope, v8_query_match_compat, "QUERY_MATCH");

        let code = r#"
const assert = (val, msg) => { if (!val) throw new Error(msg); };
assert(QUERY_MATCH.context.arguments["arg_name1"] === "123");
assert(QUERY_MATCH.context.arguments.arg_name1 === "123");
"#;
        let result = try_execute(scope, code).map(|v| v.to_rust_string_lossy(scope));
        assert_eq!(result, Ok("undefined".to_string()), "`context.arguments` failed test");

        let code = "\
QUERY_MATCH.context.code;
";
        let result = try_execute(scope, code).map(|v| v.to_rust_string_lossy(scope));
        assert_eq!(result, Ok(COMPAT_FILE_CONTENTS.to_string()), "`context.code` failed test");

        let code = "\
QUERY_MATCH.context.filename;
";
        let result = try_execute(scope, code).map(|v| v.to_rust_string_lossy(scope));
        assert_eq!(result, Ok(COMPAT_FILENAME.to_string()), "`context.filename` failed test");
    }

    /// Tests the `QueryMatch` interface on `<QueryMatchCompat>`
    #[rustfmt::skip]
    #[test]
    fn compat_layer_native_ddsa() {
        let mut runtime = cfg_test_runtime();

        let scope = &mut runtime.handle_scope();
        let stub_tsn_bridge = make_stub_tsn_bridge(scope, &[10, 20, 30]);
        attach_as_global(scope, stub_tsn_bridge, "__RUST_BRIDGE__ts_node");

        let js_class = QueryMatchCompat::try_new(scope).unwrap();
        let multi_cap =
            TSQueryCapture::<NodeId>::new_multi(Arc::<str>::from("cap_name"), vec![10, 20, 30]);
        let captures = vec![multi_cap];
        let v8_query_match = js_class.convert_to(scope, &captures.into());
        attach_as_global(scope, v8_query_match, "QUERY_MATCH");

        let code = r#"
const assert = (val, msg) => { if (!val) throw new Error(msg); };
assert(QUERY_MATCH._getManyIds("cap_name") instanceof Uint32Array, "invalid _getManyIds");
assert(Array.isArray(QUERY_MATCH.getMany("cap_name")), "invalid getMany");
assert(QUERY_MATCH._getId("cap_name") === 30, "invalid _getId");
assert(typeof QUERY_MATCH.get("cap_name") === "object", "invalid get");
"#;
        let result = try_execute(scope, code).map(|v| v.to_rust_string_lossy(scope));
        assert_eq!(result, Ok("undefined".to_string()));
    }
}
