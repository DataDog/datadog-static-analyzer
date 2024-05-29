// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

// NOTE: Because units compiled with a `cfg(test)` scope are not accessible outside
//       their module, we work around this by exposing the following functions to all compilation profiles.
//       They should only be used in unit tests.

use crate::analysis::ddsa_lib::common::{iter_v8_array, load_function};
use crate::analysis::ddsa_lib::extension::ddsa_lib;
use deno_core::v8::HandleScope;
use deno_core::{v8, ExtensionBuilder, ExtensionFileSource, ExtensionFileSourceCode};
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
fn js_all_props(scope: &mut HandleScope, value: &impl Deref<Target = v8::Object>) -> Vec<String> {
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

/// A [`deno_core::JsRuntime`] with all `ddsa_lib` ES modules exposed via `globalThis`.
pub(crate) fn cfg_test_runtime() -> deno_core::JsRuntime {
    deno_core::JsRuntime::new(deno_core::RuntimeOptions {
        extensions: vec![cfg_test_deno_ext()],
        ..Default::default()
    })
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
    let production_extension = ddsa_lib::init_ops_and_esm();
    let prod_entrypoint = production_extension.get_esm_entry_point().unwrap();

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

    ExtensionBuilder::default()
        .esm(esm_sources)
        .esm_entry_point(specifier)
        .build()
}
