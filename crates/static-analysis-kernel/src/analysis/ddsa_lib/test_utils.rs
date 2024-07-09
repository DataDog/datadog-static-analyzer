// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

// NOTE: Because units compiled with a `cfg(test)` scope are not accessible outside
//       their module, we work around this by exposing the following functions to all compilation profiles.
//       They should only be used in unit tests.

use crate::analysis::ddsa_lib::common::{
    iter_v8_array, load_function, v8_interned, v8_string, v8_uint,
};
use crate::analysis::ddsa_lib::extension::ddsa_lib;
use crate::model::common::Language;
use deno_core::v8::HandleScope;
use deno_core::{op2, v8, ExtensionBuilder, ExtensionFileSource, ExtensionFileSourceCode, Op};
use std::ops::Deref;

/// Returns true if an instance of the provided JavaScript class has exactly the `expected` property names.
/// The instance will be created by passing zero arguments to the class constructor.
///
/// This is intended for use as a canary to guard against drift between the Rust and JavaScript implementations.
pub(crate) fn js_instance_eq(class_name: &str, expected: &[&str]) -> bool {
    v8_object_eq(expected, |scope| {
        let js_class =
            load_function(scope, class_name).expect("class_name should refer to a function");
        let js_class = js_class.open(scope);
        js_class.new_instance(scope, &[]).unwrap()
    })
}

/// Returns true if the provided JavaScript class has exactly the `expected` static property names.
///
/// This is intended for use as a canary to guard against drift between the Rust and JavaScript implementations.
pub(crate) fn js_class_eq(class_name: &str, expected: &[&str]) -> bool {
    v8_object_eq(expected, |scope| {
        let js_class =
            load_function(scope, class_name).expect("class_name should refer to a function");
        let local = js_class.open(scope).to_object(scope).unwrap();
        // Hack: we get a SIGSEGV trying to access `local` as-is, so we work around this by hoisting
        // it to a global and then re-referencing it as a local.
        let global = v8::Global::new(scope, local);
        v8::Local::new(scope, global)
    })
}

/// Returns true if the `v8::Object` created by [`T`] has exactly the provided property names.
fn v8_object_eq<T>(expected: &[&str], mut object_creator: T) -> bool
where
    T: for<'s> FnMut(&mut HandleScope<'s>) -> v8::Local<'s, v8::Object>,
{
    use std::collections::HashSet;
    let mut runtime = cfg_test_runtime();
    let scope = &mut runtime.handle_scope();
    let object = object_creator(scope);

    let object_props = js_all_props(scope, &object);
    let object_props_hs = HashSet::<_>::from_iter(object_props.iter().map(String::as_str));
    let expected_hs = HashSet::from_iter(expected.iter().copied());
    expected_hs
        .symmetric_difference(&object_props_hs)
        .next()
        .is_none()
}

/// The property names in the prototype chain of an ES6 class.
/// These are excluded when enumerating the properties on a class.
#[rustfmt::skip]
const BASE_CLASS_PROTO_PROPS: &[&str] = &[
    "length", "name", "prototype", "arguments", "caller", "constructor", "apply", "bind", "call", "toString", "__defineGetter__", "__defineSetter__", "hasOwnProperty", "__lookupGetter__", "__lookupSetter__", "isPrototypeOf", "propertyIsEnumerable", "valueOf", "__proto__", "toLocaleString"
];

/// The property names in the prototype chain of an `Object` type.
/// These are excluded when enumerating the properties on an object.
#[rustfmt::skip]
const BASE_INSTANCE_PROTO_PROPS: &[&str] = &[
    "__defineGetter__", "__defineSetter__", "hasOwnProperty", "__lookupGetter__", "__lookupSetter__", "isPrototypeOf", "propertyIsEnumerable", "toString", "valueOf", "__proto__", "toLocaleString", "constructor"
];

/// A function that inspects a [`v8::Object`] and returns a list of all property names
/// (excluding property names from the object's prototype chain).
pub(crate) fn js_all_props(
    scope: &mut HandleScope,
    value: &impl Deref<Target = v8::Object>,
) -> Vec<String> {
    use std::collections::HashSet;
    /// Helper function to enumerate all properties in an object.
    fn get_all_props(scope: &mut HandleScope, object: &v8::Object) -> HashSet<String> {
        use v8::{GetPropertyNamesArgsBuilder, PropertyFilter};
        let args = GetPropertyNamesArgsBuilder::new()
            .property_filter(PropertyFilter::ALL_PROPERTIES)
            .build();
        let v8_prop_names = object.get_property_names(scope, args).unwrap();
        let mut names = HashSet::new();
        for prop_name in iter_v8_array(v8_prop_names, scope) {
            if prop_name.is_string() {
                names.insert(prop_name.to_rust_string_lossy(scope));
            }
        }
        names
    }

    let base_object = value.deref().to_object(scope).unwrap();
    let mut base_props = get_all_props(scope, &base_object);
    let ctor_name = base_object
        .get_constructor_name()
        .to_rust_string_lossy(scope);
    let prototype_props = match ctor_name.as_str() {
        // We assume that this was an ES6 class (as a "class" statement desugars into a function).
        "Function" => BASE_CLASS_PROTO_PROPS,
        _ => BASE_INSTANCE_PROTO_PROPS,
    };
    for &prop_name in prototype_props {
        base_props.remove(prop_name);
    }
    base_props.into_iter().collect()
}

/// Compiles JavaScript and executes it within the provided scope, returning the script's return value.
pub(crate) fn try_execute<'s>(
    scope: &mut HandleScope<'s>,
    code: &str,
) -> Result<v8::Local<'s, v8::Value>, String> {
    let tc_scope = &mut v8::TryCatch::new(scope);
    let code = v8_string(tc_scope, code);
    let script = v8::Script::compile(tc_scope, code, None).unwrap();
    script.run(tc_scope).ok_or_else(|| {
        let exception = tc_scope.exception().unwrap().to_rust_string_lossy(tc_scope);
        tc_scope.reset();
        exception
    })
}

/// Creates a [`tree_sitter::Tree`] from the given input and language.
pub(crate) fn parse_code(code: impl AsRef<str>, language: Language) -> tree_sitter::Tree {
    use crate::analysis::tree_sitter::get_tree_sitter_language;
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&get_tree_sitter_language(&language))
        .unwrap();
    parser.parse(code.as_ref(), None).unwrap()
}

/// A [`deno_core::JsRuntime`] with all `ddsa_lib` ES modules exposed via `globalThis`.
pub(crate) fn cfg_test_runtime() -> deno_core::JsRuntime {
    deno_core::JsRuntime::new(deno_core::RuntimeOptions {
        extensions: vec![cfg_test_deno_ext()],
        ..Default::default()
    })
}

/// An op to test the [`deno_core::op2`] macro's serialization of `Option`.
///
/// Returns `Some(123)` if `true` is passed in, or `None` if `false` is passed in.
//  Note: Due to the op2 macro implementation, we can't mark this `[cfg(test)]`
#[op2]
fn cfg_test_op_rust_option(return_some: bool) -> Option<u32> {
    return_some.then_some(123)
}

/// A [`deno_core::Extension`] that clones the ES modules from [`ddsa_lib`] and uses an
/// entrypoint that adds all module exports to `globalThis`.
///
/// We do this because we want unit tests to have access to all classes, but in the entry point
/// used for production, we don't add every class to `globalThis`. Unit tests use `v8::Script`
/// to execute JavaScript (and, because it's not an ES module, a script can't perform imports).
fn cfg_test_deno_ext() -> deno_core::Extension {
    fn leaked(string: impl ToString) -> &'static str {
        Box::leak(string.to_string().into_boxed_str())
    }

    // The extension we use in production.
    let mut production_extension = ddsa_lib::init_ops_and_esm();
    let prod_entrypoint = production_extension.get_esm_entry_point().unwrap();
    let prod_ops = production_extension.init_ops().unwrap();

    // Clone all ES modules, minus the entrypoint.
    let mut esm_sources = production_extension.get_esm_sources().clone();
    esm_sources.retain(|efs| efs.specifier != prod_entrypoint);

    // Create an entrypoint that adds all exports to `globalThis`.
    let mut entrypoint_code = String::new();
    for (idx, efs) in esm_sources.iter().enumerate() {
        // Create a unique (arbitrary) variable name for the import.
        let var_name = "a".repeat(idx + 1);
        entrypoint_code += &format!(
            r#"
import * as {} from "{}";
for (const [name, obj] of Object.entries({})) {{
    globalThis[name] = obj;
}}
"#,
            var_name, efs.specifier, var_name
        );
    }
    let entrypoint_code = leaked(entrypoint_code);
    let specifier = leaked("ext:test/__entrypoint");
    esm_sources.push(ExtensionFileSource {
        specifier,
        code: ExtensionFileSourceCode::IncludedInBinary(entrypoint_code),
    });

    // Test-environment-only ops
    let mut cfg_test_ops = vec![cfg_test_op_rust_option::DECL];
    cfg_test_ops.extend(prod_ops);

    ExtensionBuilder::default()
        .esm(esm_sources)
        .esm_entry_point(specifier)
        .ops(cfg_test_ops)
        .build()
}

/// Attaches the provided `v8_item` to the [`v8::Context::global`] with identifier `name`, overwriting
/// any previous value.
pub(crate) fn attach_as_global<'s, T>(
    scope: &mut HandleScope<'s>,
    v8_item: impl v8::Handle<Data = T>,
    name: &str,
) where
    v8::Local<'s, v8::Value>: From<v8::Local<'s, T>>,
{
    let v8_local = v8::Local::new(scope, v8_item);
    let global = scope.get_current_context().global(scope);
    let v8_key = v8_string(scope, name);
    global.set(scope, v8_key.into(), v8_local.into());
}

/// A string used as a `v8::Map` key to determine the identity of a `tree_sitter::Language` within v8.
pub(crate) const KEY_TS_LANGUAGE_PTR: &str = "CFG_TEST_TS_LANGUAGE_PTR";

/// Formats the memory address of the raw pointer that the provided `tree_sitter::Language` wraps,
/// for example: `0x104ec9e20`. This can be used to determine equivalence of two `tree_sitter::Language` within v8.
pub(crate) fn format_ts_lang_pointer(ts_language: &tree_sitter::Language) -> String {
    // We can clone the `ts_language` because a clone still has the same raw pointer as the original.
    format!("{:p}", ts_language.clone().into_raw())
}

/// Creates a stub [`v8::Map`] that represents the interface a [`TsNodeBridge`](analysis::ddsa_lib::bridge::TsNodeBridge)
/// exposes to JavaScript. The values stored are not true `TreeSitterNode` instances.
pub(crate) fn make_stub_tsn_bridge<'s>(
    scope: &mut HandleScope<'s>,
    node_ids: &[u32],
) -> v8::Local<'s, v8::Map> {
    let stub_tsn_bridge = v8::Map::new(scope);
    let s_key_id = v8_interned(scope, "id");
    for &node_id in node_ids {
        let stub_ts_node = v8::Object::new(scope);
        let v8_node_id = v8_uint(scope, node_id);
        stub_ts_node.set(scope, s_key_id.into(), v8_node_id.into());
        let s_key_abc = v8_interned(scope, "abc");
        let v8_value = v8_interned(scope, "def");
        stub_ts_node.set(scope, s_key_abc.into(), v8_value.into());
        stub_tsn_bridge.set(scope, v8_node_id.into(), stub_ts_node.into());
    }
    stub_tsn_bridge
}

/// Creates a stub [`v8::Object`] that partially implements the interface for a `RootContext`.
pub(crate) fn make_stub_root_context<'s>(
    scope: &mut HandleScope<'s>,
    arguments: &[(&str, &str)],
    filename: &str,
    file_contents: &str,
    ts_language: Option<&tree_sitter::Language>,
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
    let v8_filename = v8_string(scope, filename);
    v8_root_ctx.set(scope, s_key_filename.into(), v8_filename.into());

    let s_key_file_contents = v8_interned(scope, "fileContents");
    let v8_file_contents = v8_string(scope, file_contents);
    v8_root_ctx.set(scope, s_key_file_contents.into(), v8_file_contents.into());

    if let Some(ts_language) = ts_language {
        let metadata = crate::analysis::ddsa_lib::ts_lang::Metadata::new(scope, ts_language);
        let v8_ts_lang_obj = v8::Object::new(scope);

        let s_key_node_type = v8_interned(scope, "nodeType");
        let v8_node_type_map = metadata.node_kind_map.as_local(scope);
        v8_ts_lang_obj.set(scope, s_key_node_type.into(), v8_node_type_map.into());

        let s_key_field = v8_interned(scope, "field");
        let v8_field_map = metadata.field_map.as_local(scope);
        v8_ts_lang_obj.set(scope, s_key_field.into(), v8_field_map.into());

        let s_key_tsl_ctx = v8_interned(scope, "tsLangCtx");
        v8_root_ctx.set(scope, s_key_tsl_ctx.into(), v8_ts_lang_obj.into());
    }

    v8_root_ctx
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
