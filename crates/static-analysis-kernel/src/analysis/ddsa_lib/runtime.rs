// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::analysis;
use crate::analysis::ddsa_lib::bridge::{
    ContextBridge, QueryMatchBridge, TsNodeBridge, TsSymbolMapBridge, ViolationBridge,
};
use crate::analysis::ddsa_lib::common::{
    compile_script, create_base_runtime, v8_interned, v8_string, DDSAJsRuntimeError, Instance,
};
use crate::analysis::ddsa_lib::extension::ddsa_lib;
use crate::analysis::ddsa_lib::js;
use crate::analysis::ddsa_lib::js::{VisitArgCodeCompat, VisitArgFilenameCompat};
use crate::model::common::Language;
use crate::model::rule::RuleInternal;
use crate::model::violation;
use deno_core::v8;
use std::cell::{RefCell, RefMut};
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;

const BRIDGE_CONTEXT: &str = "__RUST_BRIDGE__context";
const BRIDGE_QUERY_MATCH: &str = "__RUST_BRIDGE__query_match";
const BRIDGE_TS_NODE: &str = "__RUST_BRIDGE__ts_node";
const BRIDGE_TS_SYMBOL: &str = "__RUST_BRIDGE__ts_symbol_lookup";
const BRIDGE_VIOLATION: &str = "__RUST_BRIDGE__violation";
const STELLA_COMPAT_FILENAME: &str = "STELLA_COMPAT_FILENAME";
const STELLA_COMPAT_FILE_CONTENTS: &str = "STELLA_COMPAT_FILE_CONTENTS";

/// Global properties that are removed from the global proxy object of the default `v8::Context` for the `JsRuntime`.
pub(crate) const DEFAULT_REMOVED_GLOBAL_PROPS: &[&str] = &[
    // `deno_core`, by default, injects its own `console` implementation.
    "console",
];

/// The Datadog Static Analyzer JavaScript runtime
pub struct JsRuntime {
    runtime: deno_core::JsRuntime,
    console: Rc<RefCell<JsConsole>>,
    bridge_context: Rc<RefCell<ContextBridge>>,
    bridge_query_match: QueryMatchBridge,
    bridge_ts_node: Rc<RefCell<TsNodeBridge>>,
    bridge_ts_symbol_map: Rc<TsSymbolMapBridge>,
    bridge_violation: ViolationBridge,
    /// A map from a rule's name to its compiled `v8::UnboundScript`.
    script_cache: Rc<RefCell<HashMap<String, v8::Global<v8::UnboundScript>>>>,
    /// A pre-allocated `tree_sitter::QueryCursor` that is re-used for each execution.
    ts_query_cursor: Rc<RefCell<tree_sitter::QueryCursor>>,
    // v8-specific
    /// A [`v8::Object`] that has been set as the prototype of the `JsRuntime`'s default context's global object.
    v8_ddsa_global: v8::Global<v8::Object>,
    // Cached strings
    s_bridge_ts_symbol_lookup: v8::Global<v8::String>,
}

impl JsRuntime {
    pub fn try_new() -> Result<Self, DDSAJsRuntimeError> {
        Self::try_new_compat(false)
    }

    pub fn try_new_compat(is_stella: bool) -> Result<Self, DDSAJsRuntimeError> {
        let mut runtime = base_js_runtime();

        // Construct the bridges and attach their underlying `v8:Global` object to the
        // default context's `globalThis` variable.
        let (context, query_match, ts_node, ts_symbols, violation, v8_ddsa_global) = {
            let scope = &mut runtime.handle_scope();
            let v8_ddsa_object = v8::Object::new(scope);

            let context = ContextBridge::try_new(scope)?;
            let v8_ctx_obj = context.as_local(scope);
            let key_ctx = v8_interned(scope, BRIDGE_CONTEXT);
            v8_ddsa_object.set(scope, key_ctx.into(), v8_ctx_obj.into());
            let context = Rc::new(RefCell::new(context));

            let query_match = QueryMatchBridge::try_new(scope)?;
            let v8_qm_array = query_match.as_local(scope);
            let key_qm = v8_interned(scope, BRIDGE_QUERY_MATCH);
            v8_ddsa_object.set(scope, key_qm.into(), v8_qm_array.into());

            let ts_node = TsNodeBridge::try_new(scope)?;
            let v8_ts_node_map = ts_node.as_local(scope);
            let key_tsn = v8_interned(scope, BRIDGE_TS_NODE);
            v8_ddsa_object.set(scope, key_tsn.into(), v8_ts_node_map.into());
            let ts_node = Rc::new(RefCell::new(ts_node));

            let ts_symbols = TsSymbolMapBridge::new();
            let ts_symbols = Rc::new(ts_symbols);
            // The actual v8::Map containing the language-specific symbols will be populated when a rule is executed.
            let key_sym = v8_interned(scope, BRIDGE_TS_SYMBOL);
            let v8_undefined = v8::undefined(scope);
            v8_ddsa_object.set(scope, key_sym.into(), v8_undefined.into());

            let violation = ViolationBridge::new(scope);
            let v8_violation_array = violation.as_local(scope);
            let key_vio = v8_interned(scope, BRIDGE_VIOLATION);
            v8_ddsa_object.set(scope, key_vio.into(), v8_violation_array.into());

            // NOTE: This is temporary scaffolding used during the transition to `ddsa_lib::JsRuntime`.
            let compat_filename = VisitArgFilenameCompat::try_new(scope)?;
            let compat_filename = compat_filename.as_local(scope);
            let key_compat_filename = v8_interned(scope, STELLA_COMPAT_FILENAME);
            v8_ddsa_object.set(scope, key_compat_filename.into(), compat_filename.into());

            // NOTE: This is temporary scaffolding used during the transition to `ddsa_lib::JsRuntime`.
            let compat_fc = VisitArgCodeCompat::try_new(scope)?;
            let compat_fc = compat_fc.as_local(scope);
            let key_compat_fc = v8_interned(scope, STELLA_COMPAT_FILE_CONTENTS);
            v8_ddsa_object.set(scope, key_compat_fc.into(), compat_fc.into());

            let v8_ctx = scope.get_current_context();
            let global_proxy = v8_ctx.global(scope);
            let true_global = global_proxy
                .get_prototype(scope)
                .expect("global proxy should always have a prototype")
                .to_object(scope)
                .expect("v8::Value should be the global object");

            true_global.set_prototype(scope, v8_ddsa_object.into());
            // Freeze the true global (NOTE: as a temporary scaffold, we conditionally do this.
            if !is_stella {
                true_global.set_integrity_level(scope, v8::IntegrityLevel::Frozen);
            }

            let v8_ddsa_global = v8::Global::new(scope, v8_ddsa_object);
            (
                context,
                query_match,
                ts_node,
                ts_symbols,
                violation,
                v8_ddsa_global,
            )
        };

        let s_bridge_ts_symbol_lookup = {
            let scope = &mut runtime.handle_scope();
            let v8_string = v8_interned(scope, BRIDGE_TS_SYMBOL);
            v8::Global::new(scope, v8_string)
        };

        let op_state = runtime.op_state();
        let mut op_state = op_state.borrow_mut();
        op_state.put(Rc::clone(&context));
        op_state.put(Rc::clone(&ts_node));
        op_state.put(Rc::clone(&ts_symbols));

        let console = Rc::new(RefCell::new(JsConsole::new()));
        op_state.put(Rc::clone(&console));

        Ok(Self {
            runtime,
            console,
            bridge_context: context,
            bridge_query_match: query_match,
            bridge_ts_node: ts_node,
            bridge_ts_symbol_map: ts_symbols,
            bridge_violation: violation,
            script_cache: Rc::new(RefCell::new(HashMap::new())),
            ts_query_cursor: Rc::new(RefCell::new(tree_sitter::QueryCursor::new())),
            v8_ddsa_global,
            s_bridge_ts_symbol_lookup,
        })
    }

    pub fn execute_rule(
        &mut self,
        source_text: &Arc<str>,
        source_tree: &Arc<tree_sitter::Tree>,
        file_name: &Arc<str>,
        rule: &RuleInternal,
        rule_arguments: &HashMap<String, String>,
    ) -> Result<Vec<violation::Violation>, DDSAJsRuntimeError> {
        let script_cache = Rc::clone(&self.script_cache);
        let mut script_cache_ref = script_cache.borrow_mut();
        if !script_cache_ref.contains_key(&rule.name) {
            let rule_script = Self::format_rule_script(&rule.code);
            let script = compile_script(&mut self.runtime.handle_scope(), &rule_script)?;
            script_cache_ref.insert(rule.name.clone(), script);
        }
        let rule_script = script_cache_ref
            .get(&rule.name)
            .expect("cache should have been populated");

        let ts_query_cursor = Rc::clone(&self.ts_query_cursor);
        let mut ts_qc = ts_query_cursor.borrow_mut();
        let mut query_cursor = rule.tree_sitter_query.with_cursor(&mut ts_qc);
        let query_matches = query_cursor
            .matches(source_tree.root_node(), source_text.as_ref())
            .filter(|captures| !captures.is_empty())
            .collect::<Vec<_>>();
        let js_violations = self.execute_rule_internal(
            source_text,
            source_tree,
            file_name,
            rule.language,
            rule_script,
            &query_matches,
            rule_arguments,
        )?;
        Ok(js_violations
            .into_iter()
            .map(|v| v.into_violation(rule.severity, rule.category))
            .collect::<Vec<_>>())
    }

    #[allow(clippy::too_many_arguments)]
    fn execute_rule_internal(
        &mut self,
        source_text: &Arc<str>,
        source_tree: &Arc<tree_sitter::Tree>,
        file_name: &Arc<str>,
        language: Language,
        rule_script: &v8::Global<v8::UnboundScript>,
        query_matches: &[analysis::tree_sitter::QueryMatch<tree_sitter::Node>],
        rule_arguments: &HashMap<String, String>,
    ) -> Result<Vec<js::Violation<Instance>>, DDSAJsRuntimeError> {
        {
            if query_matches.is_empty() {
                return Ok(vec![]);
            }

            let scope = &mut self.runtime.handle_scope();

            // Change the global object's pointer to the TSSymbolMap to the one for this specific language.
            let v8_ts_symbol_map = self
                .bridge_ts_symbol_map
                .get_map(scope, &source_tree.language());
            let opened = self.v8_ddsa_global.open(scope);
            let key_sym = v8::Local::new(scope, &self.s_bridge_ts_symbol_lookup);
            opened.set(scope, key_sym.into(), v8_ts_symbol_map.into());

            // Push data from Rust to v8
            // Update the DDSA context metadata
            let mut ctx_bridge = self.bridge_context.borrow_mut();
            let was_new_tree =
                ctx_bridge.set_root_context(scope, source_tree, source_text, file_name);
            // If the tree was new, clear the TsNodeBridge, as it contains nodes for the old tree.
            if was_new_tree {
                self.bridge_ts_node.borrow_mut().clear(scope);
            }

            // Set a file context, if applicable
            ctx_bridge.set_file_context(scope, language, source_tree, source_text);
            // Add any rule arguments
            ctx_bridge.set_rule_arguments(scope, rule_arguments);
            // Push the query matches:
            let mut ts_node_bridge = self.bridge_ts_node.borrow_mut();
            self.bridge_query_match
                .set_data(scope, query_matches, &mut ts_node_bridge);
        }

        // We use a bridge to pull violations, so we can ignore the return value with a noop handler.
        // However, because we could've had an error thrown after a mutation of the bridge globals,
        // we can't immediately return here -- the bridges need to be cleared.
        let execution_res = self.scoped_execute(rule_script, |_, _| ());

        let violations_res = self
            .bridge_violation
            .drain_collect(&mut self.runtime.handle_scope());

        self.bridge_query_match
            .clear(&mut self.runtime.handle_scope());

        if let Err(runtime_err) = execution_res {
            Err(runtime_err)
        } else {
            violations_res
        }
    }

    /// Executes a given closure within the DDSA runtime context.
    ///
    /// The return value type and the logic to produce it must be provided by the caller with the `handle_result` closure.
    /// A call may return unit:
    /// ```text
    /// runtime.scoped_execute(
    ///     &script,
    ///     |_, _| (),       // A `handle_return_value` returning unit.
    ///     None,
    /// )
    /// ```
    ///
    /// Because the script is executed in a contained scope, `v8::Local` values may not be returned. Instead,
    /// a `v8::Global` can be used to return a v8 value:
    /// ```text
    /// runtime.scoped_execute(
    ///     &script,
    ///     |scope, value| v8::Global::new(scope, value),  // A `handle_return_value` returning a v8::Global.
    ///     None,
    /// )
    /// ```
    fn scoped_execute<T, U>(
        &mut self,
        script: &v8::Global<v8::UnboundScript>,
        handle_return_value: T,
    ) -> Result<U, DDSAJsRuntimeError>
    where
        T: Fn(&mut v8::TryCatch<v8::HandleScope>, v8::Local<v8::Value>) -> U,
    {
        let scope = &mut self.runtime.handle_scope();
        // We re-use the same v8::Context for performance, and we use a combination of closures and
        // a frozen global object to achieve equivalent encapsulation to creating a new v8::Context.
        let v8_ctx = scope.get_current_context();

        let ctx_scope = &mut v8::ContextScope::new(scope, v8_ctx);
        // The v8 API uses `Option` for fallible calls, with `None` indicating a v8 execution error.
        // We need to use a `TryCatch` scope to actually be able to inspect the error type/contents.
        let tc_ctx_scope = &mut v8::TryCatch::new(ctx_scope);

        let opened = script.open(tc_ctx_scope);
        let bound_script = opened.bind_to_current_context(tc_ctx_scope);
        let execution_result = bound_script.run(tc_ctx_scope);

        let return_val = execution_result.ok_or_else(|| {
            let exception = tc_ctx_scope
                .exception()
                .expect("return value should only be `None` if an error was caught");
            let reason = exception.to_rust_string_lossy(tc_ctx_scope);
            tc_ctx_scope.reset();
            DDSAJsRuntimeError::Execution { reason }
        })?;

        Ok(handle_return_value(tc_ctx_scope, return_val))
    }

    /// Wraps a `rule_code` with the necessary DDSA hooks to pass and receive data from Rust to v8.
    fn format_rule_script(rule_code: &str) -> String {
        format!(
            "\
'use strict';

(() => {{

for (const queryMatch of globalThis.__RUST_BRIDGE__query_match) {{
    visit(queryMatch, globalThis.STELLA_COMPAT_FILENAME, globalThis.STELLA_COMPAT_FILE_CONTENTS);
}}

// The rule's JavaScript code
//////////////////////////////
{}
//////////////////////////////

}})();
",
            rule_code
        )
    }

    /// Provides a mutable reference to the underlying [`deno_core::JsRuntime`].
    ///
    /// NOTE: This is temporary scaffolding used during the transition to `ddsa_lib::JsRuntime`.
    pub fn inner_compat(&mut self) -> &mut deno_core::JsRuntime {
        &mut self.runtime
    }

    /// Provides a mutable reference to the `console` implementation.
    ///
    /// NOTE: This is temporary scaffolding used during the transition to `ddsa_lib::JsRuntime`.
    ///
    /// # Panics
    /// Panics if the `RefCell` can't be borrowed mutably.
    pub fn console_compat(&mut self) -> RefMut<'_, JsConsole> {
        self.console.borrow_mut()
    }

    /// Provides a [`v8::HandleScope`] for the underlying v8 isolate.
    #[cfg(test)]
    pub fn v8_handle_scope(&mut self) -> v8::HandleScope {
        self.runtime.handle_scope()
    }

    /// Returns the length of the `v8::Array` backing the runtime's `ViolationBridge`.
    #[cfg(test)]
    pub fn violation_bridge_v8_len(&mut self) -> usize {
        let v8_array = self
            .bridge_violation
            .as_local(&mut self.runtime.handle_scope());
        v8_array.length() as usize
    }
}

/// Constructs a [`deno_core::JsRuntime`] with the [`ddsa_lib`] extension enabled.
pub(crate) fn base_js_runtime() -> deno_core::JsRuntime {
    create_base_runtime(
        vec![ddsa_lib::init_ops_and_esm()],
        Some(Box::new(|scope, default_ctx| {
            let global_proxy = default_ctx.global(scope);
            for &prop in DEFAULT_REMOVED_GLOBAL_PROPS {
                let key = v8_string(scope, prop);
                global_proxy.delete(scope, key.into());
            }
        })),
    )
}

/// A mutable scratch space that collects the output of the `console.log` function invoked by JavaScript code.
pub(crate) struct JsConsole(Vec<String>);

impl JsConsole {
    /// Creates a new, empty `Console`.
    pub fn new() -> Self {
        Self(Vec::new())
    }

    /// Appends a string to the console.
    pub fn push(&mut self, value: impl Into<String>) {
        self.0.push(value.into())
    }

    /// Removes all lines from the `Console`, returning them as an iterator.
    pub fn drain(&mut self) -> impl Iterator<Item = String> + '_ {
        self.0.drain(..)
    }
}

#[cfg(test)]
mod tests {
    use crate::analysis::ddsa_lib::common::{
        compile_script, v8_interned, v8_uint, DDSAJsRuntimeError, Instance,
    };
    use crate::analysis::ddsa_lib::test_utils::try_execute;
    use crate::analysis::ddsa_lib::{js, JsRuntime};
    use crate::analysis::tree_sitter::{get_tree, get_tree_sitter_language};
    use crate::model::common::Language;
    use deno_core::v8;
    use std::collections::HashMap;
    use std::sync::Arc;

    /// Executes the given JavaScript rule against the given Tree, handling test-related setup boilerplate.
    fn execute_rule_internal_with_tree(
        runtime: &mut JsRuntime,
        tree: &Arc<tree_sitter::Tree>,
        source_text: &Arc<str>,
        ts_query: &str,
        rule_code: &str,
    ) -> Result<Vec<js::Violation<Instance>>, DDSAJsRuntimeError> {
        let rule_script = JsRuntime::format_rule_script(rule_code);
        let rule_script = compile_script(&mut runtime.v8_handle_scope(), &rule_script).unwrap();
        let ts_lang = get_tree_sitter_language(&Language::JavaScript);
        let ts_query = crate::analysis::tree_sitter::TSQuery::try_new(&ts_lang, ts_query).unwrap();
        let filename: Arc<str> = Arc::from("some_filename.js");

        let mut curs = ts_query.cursor();
        let q_matches = curs
            .matches(tree.root_node(), source_text.as_ref())
            .collect::<Vec<_>>();
        runtime.execute_rule_internal(
            source_text,
            tree,
            &filename,
            Language::JavaScript,
            &rule_script,
            &q_matches,
            &HashMap::new(),
        )
    }

    /// Executes the given JavaScript rule, handling test-related setup boilerplate.
    fn shorthand_execute_rule_internal(
        runtime: &mut JsRuntime,
        source_text: &str,
        filename: &str,
        ts_query: &str,
        rule_code: &str,
    ) -> Result<Vec<js::Violation<Instance>>, DDSAJsRuntimeError> {
        let source_text: Arc<str> = Arc::from(source_text);
        let filename: Arc<str> = Arc::from(filename);

        let rule_script = JsRuntime::format_rule_script(rule_code);
        let rule_script = compile_script(&mut runtime.v8_handle_scope(), &rule_script).unwrap();

        let ts_lang = get_tree_sitter_language(&Language::JavaScript);
        let tree = Arc::new(get_tree(source_text.as_ref(), &Language::JavaScript).unwrap());

        let ts_query = crate::analysis::tree_sitter::TSQuery::try_new(&ts_lang, ts_query).unwrap();

        let mut curs = ts_query.cursor();
        let q_matches = curs
            .matches(tree.root_node(), source_text.as_ref())
            .collect::<Vec<_>>();

        runtime.execute_rule_internal(
            &source_text,
            &tree,
            &filename,
            Language::JavaScript,
            &rule_script,
            &q_matches,
            &HashMap::new(),
        )
    }

    /// Ensures that the bridge globals exist within the JavaScript scope, and are of the expected type.
    #[test]
    fn bridge_global_defined() {
        let mut runtime = JsRuntime::try_new().unwrap();
        let scope = &mut runtime.runtime.handle_scope();
        let code = r#"
const assert = (val, msg) => { if (!val) throw new Error(msg); };
assert(globalThis.__RUST_BRIDGE__context instanceof RootContext, "ContextBridge global has wrong type");
assert(Array.isArray(globalThis.__RUST_BRIDGE__query_match), "QueryMatchBridge global has wrong type");
assert(typeof globalThis.__RUST_BRIDGE__ts_node === "object", "TsNodeBridge global has wrong type");
assert(Array.isArray(globalThis.__RUST_BRIDGE__violation), "ViolationBridge global has wrong type");
// An arbitrary return value to confirm that the execution completed without throwing:
123;
"#;
        let result = try_execute(scope, code).map(|v| v.uint32_value(scope).unwrap());
        assert_eq!(result, Ok(123));
    }

    /// Tests that the `v8_ddsa_global` object is the prototype of the default context's global object.
    #[test]
    fn ddsa_global_prototype_chain() {
        let mut runtime = JsRuntime::try_new().unwrap();
        let scope = &mut runtime.runtime.handle_scope();
        let global_proxy = scope.get_current_context().global(scope);
        let global = global_proxy
            .get_prototype(scope)
            .unwrap()
            .to_object(scope)
            .unwrap();
        let global_proto_hash = global.get_prototype(scope).unwrap().get_hash();
        let v8_ddsa_global_hash = runtime.v8_ddsa_global.open(scope).get_hash();
        assert_eq!(global_proto_hash, v8_ddsa_global_hash);
    }

    /// Tests that the `v8_ddsa_global` object is the prototype of the default context's global object.
    #[test]
    fn default_context_frozen_global() {
        let mut runtime = JsRuntime::try_new().unwrap();
        let scope = &mut runtime.runtime.handle_scope();
        let value = try_execute(scope, "Object.isFrozen(globalThis);").unwrap();
        assert!(value.is_true());
    }

    /// Ensures that scripts can't modify values on `v8_ddsa_global`, even though Rust can.
    /// (Although this test is partially redundant with `default_context_frozen_global`, this
    /// additionally tests that Rust can mutate the object, but that JavaScript can't).
    #[test]
    fn scoped_execute_rust_mutation_vs_javascript() {
        let mut rt = JsRuntime::try_new().unwrap();
        let type_of = "typeof __RUST_BRIDGE__ts_node;";
        let type_of = compile_script(&mut rt.v8_handle_scope(), type_of).unwrap();

        // Baseline: the bridge should be an object
        let value = rt.scoped_execute(&type_of, |s, v| v.to_rust_string_lossy(s));
        assert_eq!(value.unwrap(), "object");

        let code = r#"
'use strict';
globalThis.__RUST_BRIDGE__ts_node = 123;
typeof __RUST_BRIDGE__ts_node;
"#;
        let script = compile_script(&mut rt.v8_handle_scope(), code).unwrap();
        let value = rt.scoped_execute(&script, |s, v| v.to_rust_string_lossy(s));
        // JavaScript should not be able to mutate the value.
        assert!(value.unwrap_err().to_string().contains(
            "TypeError: Cannot add property __RUST_BRIDGE__ts_node, object is not extensible",
            // NOTE: The reason we should get the above error instead of
            // "TypeError: Cannot assign to read only property '__RUST_BRIDGE__ts_node' of object '#<Object>'"
            // is that our ddsa variables should be exposed via the global object's prototype. They
            // should not be on the global object directly (if they were, we'd get the above
            // "Cannot assign to read only property" error).
        ));

        // We need to work around the borrow checker to get a reference to the v8::Global contained
        // in `v8_ddsa_global` without needing to borrow `rt`. We achieve this by using mem::replace
        // with a stub v8::Global object, which doesn't affect execution behavior.
        let stub_obj = {
            let scope = &mut rt.v8_handle_scope();
            let stub_obj = v8::Object::new(scope);
            v8::Global::new(scope, stub_obj)
        };
        let ddsa_global = {
            let ddsa_global = std::mem::replace(&mut rt.v8_ddsa_global, stub_obj);
            let scope = &mut rt.v8_handle_scope();

            let opened = ddsa_global.open(scope);
            let key = v8_interned(scope, "__RUST_BRIDGE__ts_node");
            let arbitrary_number = v8_uint(scope, 123);
            opened.set(scope, key.into(), arbitrary_number.into());
            ddsa_global
        };
        // Restore the original `ddsa_global`, dropping the `stub_obj` v8::Global.
        drop(std::mem::replace(&mut rt.v8_ddsa_global, ddsa_global));

        let value = rt.scoped_execute(&type_of, |sc, value| value.to_rust_string_lossy(sc));
        // Rust should be able to mutate the value.
        assert_eq!(value.unwrap(), "number");
    }

    /// Tests that `scoped_execute` re-uses the default context. We use the global proxy's identity hash
    /// to determine context equivalence.
    #[test]
    fn scoped_execute_uses_default_context() {
        let mut runtime = JsRuntime::try_new().unwrap();

        // Any arbitrary, valid JavaScript code works here. We are only running a script to
        // inspect the v8 context that it executes within.
        let script = compile_script(&mut runtime.v8_handle_scope(), "// Test execution").unwrap();

        let default_ctx_id_hash = {
            let scope = &mut runtime.runtime.handle_scope();
            let global_proxy = scope.get_current_context().global(scope);
            global_proxy.get_identity_hash()
        };

        let scoped_exe_id_hash = runtime
            .scoped_execute(&script, |scope, _| {
                // (While in general, this function will be used to map the `v8::Value` of the script's output,
                // we use it here in this test to inspect the context).

                // In this case `get_current_context` will be the context the script is running in,
                // not necessarily the default context of the v8 isolate.
                let global_proxy = scope.get_current_context().global(scope);
                global_proxy.get_identity_hash()
            })
            .unwrap();
        assert_eq!(default_ctx_id_hash, scoped_exe_id_hash);
    }

    /// Ensures that `execute_rule_internal` can define functions, but they don't mutate the v8 context.
    #[test]
    fn execute_rule_internal_no_side_effects() {
        let mut rt = JsRuntime::try_new().unwrap();
        let text = "const someName = 123;";
        let filename = "some_filename.js";
        let ts_query = "(identifier) @cap_name";
        let rule = r#"
function visit(captures) {
    const abc = 123;
    console.log(abc);
}
"#;
        // Because `globalThis` should be frozen, attempting to declare a function would normally
        // throw an error (e.g. "TypeError: Cannot add property visit, object is not extensible").
        // The function declaration will only work if we're doing it within an anonymous function.
        shorthand_execute_rule_internal(&mut rt, text, filename, ts_query, rule).unwrap();
        let lines = rt.console.borrow_mut().drain().collect::<Vec<_>>();
        assert_eq!(lines[0], "123");
    }

    /// `scoped_execute` catches and reports JavaScript errors.
    #[test]
    fn scoped_execute_runtime_error() {
        let mut runtime = JsRuntime::try_new().unwrap();

        let code = "abc;";
        let script = compile_script(&mut runtime.v8_handle_scope(), code).unwrap();
        let err = runtime
            .scoped_execute(&script, |tc_scope, val| val.to_rust_string_lossy(tc_scope))
            .unwrap_err();
        assert!(err
            .to_string()
            .contains("ReferenceError: abc is not defined"));
    }

    #[test]
    fn execute_rule_internal() {
        let mut rt = JsRuntime::try_new().unwrap();
        let source_text = "const someName = 123; const protectedName = 456;";
        let filename = "some_filename.js";
        let ts_query = r#"
((identifier) @cap_name (#eq? @cap_name "protectedName"))
"#;
        let rule_code = r#"
function visit(captures) {
    const node = captures.get("cap_name");
    const error = buildError(
        node.start.line,
        node.start.col,
        node.end.line,
        node.end.col,
        `\`${node.text}\` is a protected variable name`
    );
    addError(error);
}
"#;

        let violations =
            shorthand_execute_rule_internal(&mut rt, source_text, filename, ts_query, rule_code)
                .unwrap();

        assert_eq!(violations.len(), 1);
        let violation = violations.first().unwrap();

        let expected = js::Violation {
            start_line: 1,
            start_col: 29,
            end_line: 1,
            end_col: 42,
            message: "`protectedName` is a protected variable name".to_string(),
            fixes: None,
            _pd: Default::default(),
        };
        assert_eq!(*violation, expected);
    }

    /// Tests that an error during JavaScript execution doesn't leave a bridge in a dirty state
    /// QueryMatch - cleared
    /// Violation  - cleared
    /// TsNode     - preserved
    #[test]
    fn execute_rule_internal_bridge_state() {
        let mut rt = JsRuntime::try_new().unwrap();
        let source_text = "123; 456; 789;";
        let filename = "some_filename.js";
        let ts_query = "(number) @cap_name";
        let rule_code = r#"
function visit(captures) {
    const node = captures.get("cap_name");
    if (node.text === "456") {
        throw new Error("Sample error between query matches");
    }
    const error = buildError(1, 2, 3, 4, "Error text");
    addError(error);
}
"#;

        let violations_res =
            shorthand_execute_rule_internal(&mut rt, source_text, filename, ts_query, rule_code);

        assert!(violations_res.is_err());
        assert_eq!(rt.bridge_query_match.len(), 0);
        assert_eq!(rt.violation_bridge_v8_len(), 0);
        assert_eq!(rt.bridge_ts_node.borrow().len(), 3);
    }

    /// Tests that we don't call out to v8 to execute JavaScript if there are no `query_matches`.
    #[test]
    fn execute_rule_internal_no_unnecessary_invocations() {
        let mut rt = JsRuntime::try_new().unwrap();
        let source_text = "123; 456; 789;";
        let filename = "some_filename.js";
        let ts_query = "(identifier) @cap_name";
        let rule_code = r#"
function visit(captures) {}

throw new Error("script should not have been executed");
"#;

        let violations_res =
            shorthand_execute_rule_internal(&mut rt, source_text, filename, ts_query, rule_code);
        assert!(violations_res.unwrap().is_empty());
    }

    /// Tests that the compatibility layer allows a rule written for the stella runtime to execute.
    #[test]
    fn stella_compat_execute_rule_internal() {
        let mut rt = JsRuntime::try_new().unwrap();
        let source_text = "const someName = 123; const protectedName = 456;";
        let filename = "some_filename.js";
        let ts_query = r#"
((identifier) @cap_name (#eq? @cap_name "protectedName"))
"#;
        let rule_code = r#"
function visit(query, filename, code) {
    const node = query.captures["cap_name"];
    const nodeText = getCodeForNode(node, code);
    const error = buildError(
        node.start.line,
        node.start.col,
        node.end.line,
        node.end.col,
        `\`${nodeText}\` is a protected variable name`
    );
    addError(error);
}
"#;

        let violations =
            shorthand_execute_rule_internal(&mut rt, source_text, filename, ts_query, rule_code)
                .unwrap();

        assert_eq!(violations.len(), 1);
        let violation = violations.first().unwrap();

        let expected = js::Violation {
            start_line: 1,
            start_col: 29,
            end_line: 1,
            end_col: 42,
            message: "`protectedName` is a protected variable name".to_string(),
            fixes: None,
            _pd: Default::default(),
        };
        assert_eq!(*violation, expected);
    }

    /// Tests that the runtime's `TsNodeBridge` state persists between rule executions on the same
    /// tree but is cleared when the tree changes.
    #[test]
    fn runtime_ts_node_bridge_state() {
        let mut rt = JsRuntime::try_new().unwrap();
        let ts_query_1 = "(number) @cap_name";
        let rule_code_1 = r#"
function visit(captures) {
    const node = captures.get("cap_name");
    console.log(node.id);
}
"#;
        let ts_query_2 = "(identifier) @other_cap_name";
        let rule_code_2 = r#"
function visit(captures) {
    const node = captures.get("other_cap_name");
    console.log(node.id);
}
"#;
        let source: Arc<str> = Arc::from("const alpha = 123; const bravo = 456;");
        let tree1 = Arc::new(get_tree(source.as_ref(), &Language::JavaScript).unwrap());

        execute_rule_internal_with_tree(&mut rt, &tree1, &source, ts_query_1, rule_code_1).unwrap();
        let log = rt.console.borrow_mut().drain().collect::<Vec<_>>();
        assert_eq!(log, vec!["0".to_string(), "1".to_string()]);

        execute_rule_internal_with_tree(&mut rt, &tree1, &source, ts_query_2, rule_code_2).unwrap();
        let log = rt.console.borrow_mut().drain().collect::<Vec<_>>();
        // Ids are assigned sequentially, so a start id of 2 means the bridge already contained 2 nodes.
        assert_eq!(log, vec!["2".to_string(), "3".to_string()]);

        let source: Arc<str> = Arc::from("const echo = 888; const foxtrot = 999;");
        let tree2 = Arc::new(get_tree(source.as_ref(), &Language::JavaScript).unwrap());
        execute_rule_internal_with_tree(&mut rt, &tree2, &source, ts_query_1, rule_code_1).unwrap();
        let log = rt.console.borrow_mut().drain().collect::<Vec<_>>();
        assert_eq!(log, vec!["0".to_string(), "1".to_string()]);
    }

    /// Tests that `console` resolves to our `DDSA_Console` implementation, not deno's
    #[test]
    fn ddsa_console_global() {
        let mut runtime = JsRuntime::try_new().unwrap();
        let code = "console instanceof DDSA_Console;";
        let script = compile_script(&mut runtime.v8_handle_scope(), code).unwrap();
        let correct_instance = runtime.scoped_execute(&script, |_, value| value.is_true());
        assert!(correct_instance.unwrap());
    }

    /// Tests that `TreeSitterNode` serializes to a human-friendly representation via the DDSA_Console.
    #[test]
    fn ddsa_console_ts_node() {
        let mut rt = JsRuntime::try_new().unwrap();
        let source_text = "const abc = 123;";
        let filename = "some_filename.js";
        let ts_query = r#"
(identifier) @cap_name
"#;
        let rule_code = r#"
function visit(captures) {
    const node = captures.get("cap_name");
    console.log(node);
    // The special serialization applies, even if the object is nested.
    console.log([{abc: node}]);
}
"#;
        shorthand_execute_rule_internal(&mut rt, source_text, filename, ts_query, rule_code)
            .unwrap();
        let console_lines = rt.console.borrow_mut().drain().collect::<Vec<_>>();
        let expected = r#"{"type":"identifier","start":{"line":1,"col":7},"end":{"line":1,"col":10},"text":"abc"}"#;
        assert_eq!(console_lines[0], expected);
        let expected_nested = format!("[{{\"abc\":{}}}]", expected);
        assert_eq!(console_lines[1], expected_nested);
    }

    #[test]
    fn op_ts_node_children() {
        let mut rt = JsRuntime::try_new().unwrap();
        let source_text = "function echo(a, b, c) {}";
        let filename = "some_filename.js";
        let ts_query = r#"
((function_declaration
    (formal_parameters) @paramList))
"#;
        let noop = r#"
function visit(captures) { }
"#;
        let get_children = r#"
function visit(captures) {
    const node = captures.get("paramList");
    const children = node.children;
    console.log(children);
}
"#;
        // First run a no-op rule to assert that only 1 (captured) node is sent to the bridge.
        shorthand_execute_rule_internal(&mut rt, source_text, filename, ts_query, noop).unwrap();
        assert_eq!(rt.bridge_ts_node.borrow().len(), 1);
        // Then execute the rule that fetches the children of the node.
        shorthand_execute_rule_internal(&mut rt, source_text, filename, ts_query, get_children)
            .unwrap();
        let console_lines = rt.console.borrow_mut().drain().collect::<Vec<_>>();
        // We should've newly pushed the captured node's 7 children to the bridge.
        assert_eq!(rt.bridge_ts_node.borrow().len(), 8);
        let expected = r#"[{"type":"","start":{"line":1,"col":14},"end":{"line":1,"col":15},"text":"("},{"type":"identifier","start":{"line":1,"col":15},"end":{"line":1,"col":16},"text":"a"},{"type":"","start":{"line":1,"col":16},"end":{"line":1,"col":17},"text":","},{"type":"identifier","start":{"line":1,"col":18},"end":{"line":1,"col":19},"text":"b"},{"type":"","start":{"line":1,"col":19},"end":{"line":1,"col":20},"text":","},{"type":"identifier","start":{"line":1,"col":21},"end":{"line":1,"col":22},"text":"c"},{"type":"","start":{"line":1,"col":22},"end":{"line":1,"col":23},"text":")"}]"#;
        assert_eq!(console_lines[0], expected);
    }
}
