// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

// NOTE: Because units compiled with a `cfg(test)` scope are not accessible outside
//       their module, we work around this by exposing the following functions to all compilation profiles.
//       They should only be used in unit tests.

use crate::analysis::ddsa_lib::common::{
    iter_v8_array, load_function, v8_interned, v8_string, v8_uint, DDSAJsRuntimeError,
};
use crate::analysis::ddsa_lib::extension::ddsa_lib;
use crate::analysis::ddsa_lib::runtime::{make_base_deno_core_runtime, ExecutionResult};
use crate::analysis::ddsa_lib::v8_platform::V8Platform;
use crate::analysis::ddsa_lib::JsRuntime;
use crate::analysis::tree_sitter::{get_tree, get_tree_sitter_language};
use crate::model::common::Language;
use crate::model::rule::{RuleCategory, RuleInternal, RuleSeverity};
use deno_core::v8::HandleScope;
use deno_core::{v8, ExtensionFileSource};
use std::borrow::Cow;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::ops::Deref;
use std::sync::Arc;
use std::time::Duration;

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
    let mut runtime = cfg_test_v8().deno_core_rt();
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

/// A [`deno_core::Extension`] that clones the ES modules from [`ddsa_lib`] and uses an
/// entrypoint that adds all module exports to `globalThis`.
///
/// We do this because we want unit tests to have access to all classes, but in the entry point
/// used for production, we don't add every class to `globalThis`. Unit tests use `v8::Script`
/// to execute JavaScript (and, because it's not an ES module, a script can't perform imports).
fn cfg_test_deno_ext() -> deno_core::Extension {
    // The extension we use in production.
    let mut production_extension = ddsa_lib::init_ops_and_esm();
    let prod_entrypoint = production_extension.get_esm_entry_point().unwrap();
    let prod_ops = production_extension.init_ops().to_owned();
    #[allow(unused_mut)]
    let mut ops = prod_ops;

    // Clone all ES modules, minus the entrypoint.
    let mut esm_sources = production_extension.get_esm_sources().to_owned();
    esm_sources.retain(|efs| efs.specifier != prod_entrypoint);

    // Add additional cfg(test) ES modules
    #[cfg(test)]
    {
        use crate::analysis::ddsa_lib::extension::ddsa_lib_cfg_test;
        let mut cfg_test_extension = ddsa_lib_cfg_test::init_ops_and_esm();
        esm_sources.extend(cfg_test_extension.get_esm_sources().to_owned());
        ops.extend(cfg_test_extension.init_ops().to_owned());
    }

    // Create an entrypoint that adds all exports to `globalThis`.
    let mut entrypoint_code = "'use strict';\n".to_string();
    for (idx, efs) in esm_sources.iter().enumerate() {
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
    entrypoint_code += "
globalThis.console = new DDSA_Console();
globalThis.ddsa = new DDSA();
globalThis.__ddsaPrivate__ = new DDSAPrivate();
";
    let entrypoint_code = entrypoint_code;
    let specifier = "ext:test/__entrypoint";
    esm_sources.push(ExtensionFileSource::new_computed(
        specifier,
        Arc::from(entrypoint_code),
    ));

    deno_core::Extension {
        name: "cfg_test_ddsa_lib",
        esm_entry_point: Some(specifier),
        esm_files: Cow::Owned(esm_sources),
        ops: Cow::Owned(ops),
        ..Default::default()
    }
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

/// Additional options that are used for a subset of tests
// (This keeps the function signature of `shorthand_execute_rule` concise)
#[derive(Debug, Default, Clone)]
pub(crate) struct ExecuteOptions<'a> {
    file_name: Option<&'a str>,
    rule_arguments: Option<&'a HashMap<String, String>>,
    timeout: Option<Duration>,
}

/// Executes the provided code and tree-sitter query as a [`RuleCategory::Unknown`] and
/// [`RuleSeverity::Error`] rule, handling test-related setup boilerplate.
pub(crate) fn shorthand_execute_rule(
    runtime: &mut JsRuntime,
    language: Language,
    ts_query: &str,
    js_code: &str,
    source_text: &str,
    options: Option<ExecuteOptions>,
) -> Result<ExecutionResult, DDSAJsRuntimeError> {
    let mut hasher = std::hash::DefaultHasher::new();
    (language, &js_code, &ts_query).hash(&mut hasher);
    // A hash used to generate deterministic values for optional arguments.
    let hash = hasher.finish();
    let rule_name = format!("rule-{hash:016x}");

    let source_text: Arc<str> = Arc::from(source_text);
    let tree = get_tree(source_text.as_ref(), &language).unwrap();
    let tree = Arc::new(tree);

    let filename: Arc<str> = Arc::from(
        options
            .as_ref()
            .and_then(|o| o.file_name.map(ToString::to_string))
            .unwrap_or(format!("file-{hash:016x}")),
    );
    let arguments = options
        .as_ref()
        .and_then(|o| o.rule_arguments.cloned())
        .unwrap_or_default();
    let timeout = options.as_ref().and_then(|o| o.timeout);

    let ts_lang = get_tree_sitter_language(&language);
    let query = crate::analysis::tree_sitter::TSQuery::try_new(&ts_lang, ts_query).unwrap();
    let rule = RuleInternal {
        name: rule_name,
        short_description: None,
        description: None,
        category: RuleCategory::Unknown,
        severity: RuleSeverity::Error,
        language,
        code: js_code.to_string(),
        tree_sitter_query: query,
    };

    runtime.execute_rule(&source_text, &tree, &filename, &rule, &arguments, timeout)
}

/// A wrapper around a [`tree_sitter::Tree`] providing shorthand tree inspection functions.
#[derive(Debug, Clone)]
pub(crate) struct TsTree {
    tree: Arc<tree_sitter::Tree>,
    text: String,
}

impl TsTree {
    pub fn new(source_text: &str, lang: Language) -> Self {
        let tree = Arc::new(get_tree(source_text, &lang).unwrap());
        Self::from_parts(tree, source_text)
    }

    pub fn from_parts(tree: Arc<tree_sitter::Tree>, text: impl Into<String>) -> Self {
        let text = text.into();
        Self { tree, text }
    }

    pub fn tree(&self) -> Arc<tree_sitter::Tree> {
        Arc::clone(&self.tree)
    }

    /// Returns the text for the provided node.
    pub fn text(&self, node: tree_sitter::Node) -> &str {
        node.utf8_text(self.text.as_bytes()).unwrap()
    }

    /// Returns all named `tree_sitter::Node`s matching `text` and `kind`, if provided.
    pub fn find_named_nodes<'t>(
        &'t self,
        text: Option<&str>,
        kind: Option<&str>,
    ) -> Vec<tree_sitter::Node<'t>> {
        self.find_nodes(text, kind)
            .iter()
            .filter(|&node| node.is_named())
            .copied()
            .collect()
    }

    /// Returns all `tree_sitter::Node`s matching `text` and `kind`, if provided.
    pub fn find_nodes<'t>(
        &'t self,
        text: Option<&str>,
        kind: Option<&str>,
    ) -> Vec<tree_sitter::Node<'t>> {
        Self::preorder_nodes(self.tree.root_node())
            .iter()
            .filter(|&node| {
                text.map(|t| node.utf8_text(self.text.as_bytes()).unwrap() == t)
                    .unwrap_or(true)
                    && kind.map(|k| node.kind() == k).unwrap_or(true)
            })
            .copied()
            .collect()
    }

    /// Returns a Vec of the root's nodes in preorder.
    pub fn preorder_nodes(root: tree_sitter::Node) -> Vec<tree_sitter::Node> {
        let mut cursor = root.walk();
        let mut nodes = vec![];
        'outer: loop {
            nodes.push(cursor.node());
            if cursor.goto_first_child() {
                continue;
            }
            if cursor.goto_next_sibling() {
                continue;
            }
            while !cursor.goto_next_sibling() {
                if !cursor.goto_parent() {
                    // Reached the root
                    break 'outer;
                }
            }
        }
        nodes
    }
}

/// A ZWT used to indicate that a [`V8Platform`] is operating in a test environment.
#[derive(Debug, Copy, Clone)]
pub struct CfgTest;

pub fn cfg_test_v8() -> V8Platform<CfgTest> {
    static V8_PLATFORM_INIT: std::sync::Once = std::sync::Once::new();

    V8_PLATFORM_INIT.call_once(|| {
        // When running with PKU support, only the thread that initialized the v8 platform (or that thread's
        // spawned children) can access the v8 isolates. This is problematic in `cargo` unit tests because there is
        // currently no way that we can guarantee that the main thread will be the first to initialize v8.
        // In order to get around this, we can use the "unprotected" v8 platform.
        let platform = v8::new_unprotected_default_platform(0, false);
        let shared_platform = platform.make_shared();
        deno_core::JsRuntime::init_platform(Some(shared_platform));
    });

    V8Platform::<CfgTest>(std::marker::PhantomData)
}

impl V8Platform<CfgTest> {
    pub fn new_runtime(&self) -> JsRuntime {
        let test_deno_core_runtime = self.deno_core_rt();
        JsRuntime::try_new(test_deno_core_runtime).unwrap()
    }

    pub fn deno_core_rt(&self) -> deno_core::JsRuntime {
        make_base_deno_core_runtime(vec![cfg_test_deno_ext()])
    }
}
