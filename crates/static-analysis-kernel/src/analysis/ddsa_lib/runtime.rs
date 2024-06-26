// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::analysis;
use crate::analysis::ddsa_lib::bridge::{
    ContextBridge, QueryMatchBridge, TsNodeBridge, TsSymbolMapBridge, ViolationBridge,
};
use crate::analysis::ddsa_lib::common::{
    compile_script, v8_interned, DDSAJsRuntimeError, Instance,
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
    /// A JavaScript "global" object (i.e. `globalThis`) augmented with ddsa variables. This is _not_
    /// a global proxy object, but rather, the global object itself.
    ///
    /// This is cached so that whenever we create a new v8 context, we can explicitly set this as the
    /// prototype of the context's global proxy object, exposing all ddsa globals to the v8 context.
    /// Without caching, we'd have to create this object every time.
    ///
    /// NOTE: This is a hack to work around the fact `rusty_v8` does not currently have bindings for 100% of the C++ API.
    ///
    /// In the C++ API, we wouldn't need to do this because in order to "share" the global object
    /// across contexts, we would "Detach" the global and create a new v8 Context with it directly, like so:
    /// ```text
    /// // C++
    /// auto ddsa_global = prev_ctx->Global();
    /// prev_ctx->Exit();
    /// prev_ctx->DetachGlobal();
    /// auto new_ctx = v8::Context::New(/* isolate, template */, ddsa_global)
    /// ```
    /// But we cannot as easily implement this in Rust because `rusty_v8` does not currently support passing
    /// in a `global_object` (currently, it always passes in null).
    ddsa_v8_ctx_true_global: v8::Global<v8::Object>,
    // Cached strings
    s_bridge_ts_symbol_lookup: v8::Global<v8::String>,
}

impl JsRuntime {
    pub fn try_new() -> Result<Self, DDSAJsRuntimeError> {
        let mut runtime = base_js_runtime();

        // Construct the bridges and attach their underlying `v8:Global` object to the
        // default context's `globalThis` variable.
        let (context, query_match, ts_node, ts_symbols, violation, ctx_true_global) = {
            let scope = &mut runtime.handle_scope();
            let v8_ctx = scope.get_current_context();
            let global_proxy = v8_ctx.global(scope);
            let true_global = global_proxy
                .get_prototype(scope)
                .expect("global proxy should always have a prototype")
                .to_object(scope)
                .expect("global proxy prototype should always be an object");

            let context = ContextBridge::try_new(scope)?;
            let v8_ctx_obj = context.as_local(scope);
            let key_ctx = v8_interned(scope, BRIDGE_CONTEXT);
            true_global.set(scope, key_ctx.into(), v8_ctx_obj.into());
            let context = Rc::new(RefCell::new(context));

            let query_match = QueryMatchBridge::try_new(scope)?;
            let v8_qm_array = query_match.as_local(scope);
            let key_qm = v8_interned(scope, BRIDGE_QUERY_MATCH);
            true_global.set(scope, key_qm.into(), v8_qm_array.into());

            let ts_node = TsNodeBridge::try_new(scope)?;
            let v8_ts_node_map = ts_node.as_local(scope);
            let key_tsn = v8_interned(scope, BRIDGE_TS_NODE);
            true_global.set(scope, key_tsn.into(), v8_ts_node_map.into());
            let ts_node = Rc::new(RefCell::new(ts_node));

            let ts_symbols = TsSymbolMapBridge::new();
            let ts_symbols = Rc::new(ts_symbols);
            // The actual v8::Map containing the language-specific symbols will be populated when a rule is executed.
            let key_sym = v8_interned(scope, BRIDGE_TS_SYMBOL);
            let v8_undefined = v8::undefined(scope);
            true_global.set(scope, key_sym.into(), v8_undefined.into());

            let violation = ViolationBridge::new(scope);
            let v8_violation_array = violation.as_local(scope);
            let key_vio = v8_interned(scope, BRIDGE_VIOLATION);
            true_global.set(scope, key_vio.into(), v8_violation_array.into());

            // NOTE: This is temporary scaffolding used during the transition to `ddsa_lib::JsRuntime`.
            let compat_filename = VisitArgFilenameCompat::try_new(scope)?;
            let compat_filename = compat_filename.as_local(scope);
            let key_compat_filename = v8_interned(scope, STELLA_COMPAT_FILENAME);
            true_global.set(scope, key_compat_filename.into(), compat_filename.into());

            // NOTE: This is temporary scaffolding used during the transition to `ddsa_lib::JsRuntime`.
            let compat_fc = VisitArgCodeCompat::try_new(scope)?;
            let compat_fc = compat_fc.as_local(scope);
            let key_compat_fc = v8_interned(scope, STELLA_COMPAT_FILE_CONTENTS);
            true_global.set(scope, key_compat_fc.into(), compat_fc.into());

            let ctx_true_global = v8::Global::new(scope, true_global);
            (
                context,
                query_match,
                ts_node,
                ts_symbols,
                violation,
                ctx_true_global,
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
            ddsa_v8_ctx_true_global: ctx_true_global,
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
            let opened = self.ddsa_v8_ctx_true_global.open(scope);
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
        let v8_ctx = v8::Context::new(scope);

        // `rusty_v8` doesn't implement bindings for 100% of the C++ API (e.g. `v8::Context::new` in Rust is
        // unable to pass in a global object, whereas in C++ it can).
        // We work around this here by explicitly setting the global object's prototype after creating the v8 context.
        // NOTE: The terminology can be confusing -- the global object is the prototype of the "global proxy" object,
        // which `rusty_v8` exposes as `Context::global`. If we were to set the prototype of the "global proxy" object,
        // instead of the (true) "global object", the changes wouldn't be seen by JavaScript code.
        let global_proxy = v8_ctx.global(scope);
        let true_global = global_proxy
            .get_prototype(scope)
            .expect("global proxy should always have a prototype")
            .to_object(scope)
            .expect("global proxy prototype should always be an object");

        let v8_ddsa_true_global = v8::Local::new(scope, &self.ddsa_v8_ctx_true_global);
        true_global.set_prototype(scope, v8_ddsa_true_global.into());

        // Set up a new ContextScope so the slate is clean between rule executions. This is necessary
        // because, for performance, we share both a v8 isolate and a global object across all rule executions.
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
            r#"
for (const queryMatch of globalThis.__RUST_BRIDGE__query_match) {{
    visit(queryMatch, globalThis.STELLA_COMPAT_FILENAME, globalThis.STELLA_COMPAT_FILE_CONTENTS);
}}

// The rule's JavaScript code
//////////////////////////////
{}
//////////////////////////////
"#,
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
    deno_core::JsRuntime::new(deno_core::RuntimeOptions {
        extensions: vec![ddsa_lib::init_ops_and_esm()],
        ..Default::default()
    })
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
        compile_script, v8_interned, DDSAJsRuntimeError, Instance,
    };
    use crate::analysis::ddsa_lib::test_utils::{js_all_props, try_execute};
    use crate::analysis::ddsa_lib::{js, JsRuntime};
    use crate::analysis::tree_sitter::{get_tree, get_tree_sitter_language};
    use crate::model::common::Language;
    use deno_core::v8;
    use std::collections::{HashMap, HashSet};
    use std::sync::Arc;

    /// A shorthand helper to set a key/value pair to the runtime's true global object.
    fn set_runtime_global<F>(runtime: &mut JsRuntime, key: &str, value_gen: F)
    where
        for<'s> F: Fn(&mut v8::HandleScope<'s>) -> v8::Local<'s, v8::Value>,
    {
        let scope = &mut runtime.runtime.handle_scope();
        let key = v8_interned(scope, key);
        let global = runtime.ddsa_v8_ctx_true_global.open(scope);
        let value = value_gen(scope);
        global.set(scope, key.into(), value);
    }

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

    /// Tests that `scoped_execute` has access to the same global variables that the v8 isolate's
    /// default context does, but that it's not the same v8 context. We use the global proxy object's
    /// identity hash as a key to indicate v8 context equivalence.
    #[test]
    fn scoped_execute_context_parity() {
        let mut runtime = JsRuntime::try_new().unwrap();
        // Add an arbitrary global variable to confirm that a non-default context is being used.
        const ARBITRARY_NAME: &str = "arbitraryVariableName";

        set_runtime_global(&mut runtime, ARBITRARY_NAME, |scope| {
            v8::Integer::new(scope, 123).into()
        });

        // Any arbitrary, valid JavaScript code works here. We are only running a script to
        // inspect the v8 context that it executes within.
        let script = compile_script(&mut runtime.v8_handle_scope(), "// Test execution").unwrap();

        let (default_ctx_id_hash, default_ctx_global_proxy_props) = {
            let scope = &mut runtime.runtime.handle_scope();
            let global_proxy = scope.get_current_context().global(scope);
            let id_hash = global_proxy.get_identity_hash();
            let props = js_all_props(scope, &global_proxy);
            let props: HashSet<String> = HashSet::from_iter(props);
            (id_hash, props)
        };
        let (scoped_exe_id_hash, scoped_global_proxy_props) = runtime
            .scoped_execute(&script, |scope, _| {
                // While in general, this function will be used to map the `v8::Value` of the script's output,
                // we use it here in this test to inspect the context's global variables.
                let global_proxy = scope.get_current_context().global(scope);
                let id_hash = global_proxy.get_identity_hash();
                let props = js_all_props(scope, &global_proxy);
                let props: HashSet<String> = HashSet::from_iter(props);
                (id_hash, props)
            })
            .unwrap();

        // Ensure we're not just using vanilla contexts. These would have the same globals, sidestepping the intended test.
        assert!(default_ctx_global_proxy_props.contains(ARBITRARY_NAME));
        assert!(scoped_global_proxy_props.contains(ARBITRARY_NAME));

        let prop_diff = default_ctx_global_proxy_props
            .symmetric_difference(&scoped_global_proxy_props)
            .collect::<HashSet<&String>>();
        assert!(prop_diff.is_empty());
        assert_ne!(default_ctx_id_hash, scoped_exe_id_hash);
    }

    /// Ensures that properties edited on `globalThis` do not persist between executions.
    #[rustfmt::skip]
    #[test]
    fn scoped_execute_isolated_globals() {
        let mut runtime = JsRuntime::try_new().unwrap();
        set_runtime_global(&mut runtime, "CONTEXT_GLOBAL", |scope| {
            // Assign the value to an arbitrary type that is "pass by sharing" -- in this case, an "object".
            // This allows us to confirm equality of the pointer, not just the value.
            let key = v8_interned(scope, "foo");
            let value = v8::Integer::new(scope, 123);
            let v8_obj = v8::Object::new(scope);
            v8_obj.set(scope, key.into(), value.into());
            v8_obj.into()
        });

        let mut execute_code = |code: &str| -> String {
            let script = compile_script(&mut runtime.v8_handle_scope(), code).unwrap();
            runtime.scoped_execute(&script, |scope, val| val.to_rust_string_lossy(scope)).unwrap()
        };

        let typeof_check = "typeof globalThis.CONTEXT_GLOBAL;";
        // Test mutations of existing properties
        let cases = [
            "\
globalThis.CONTEXT_GLOBAL = 123;
typeof globalThis.CONTEXT_GLOBAL;
",
            "\
CONTEXT_GLOBAL = 123;
typeof globalThis.CONTEXT_GLOBAL;
",
        ];
        for mutation_code in cases {
            // First ensure the global exists within the runtime.
            assert_eq!(execute_code(typeof_check), "object");
            // Then confirm the mutation worked within the scoped context.
            assert_eq!(execute_code(mutation_code), "number");
            // And then assert it doesn't persist.
            assert_eq!(execute_code(typeof_check), "object", "global mutation leaked outside the execution context");
        }

        // Test addition of properties
        assert_eq!(execute_code("typeof globalThis.addedProperty"), "undefined");
        let added_property = "\
globalThis.addedProperty = 123;
typeof globalThis.addedProperty;
";
        assert_eq!(execute_code(added_property), "number");
        // Back to a clean slate
        assert_eq!(execute_code("typeof globalThis.addedProperty"), "undefined");
    }

    /// Ensures that the v8 context used for execution isn't mutated by a script execution.
    #[test]
    fn scoped_execute_no_side_effects() {
        let mut runtime = JsRuntime::try_new().unwrap();

        let code = "const abc = 123; abc;";
        let script = compile_script(&mut runtime.v8_handle_scope(), code).unwrap();
        (0..2).for_each(|_| {
            let exe_result =
                runtime.scoped_execute(&script, |tc_scope, val| val.to_rust_string_lossy(tc_scope));
            // If the v8 context a script runs in can be mutated by a prior script, on the second iteration, we'd get the following error:
            // `SyntaxError: Identifier 'abc' has already been declared`
            // Thus, any non-error indicates test success (though we check the value just to be sure).
            assert!(exe_result.is_ok_and(|value| value == "123"));
        });
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
    // TODO (JF): When the deno console issue is resolved, this will be removed
    const console = Object.getPrototypeOf(globalThis).console;
    console.log(node.id);
}
"#;
        let ts_query_2 = "(identifier) @other_cap_name";
        let rule_code_2 = r#"
function visit(captures) {
    const node = captures.get("other_cap_name");
    // TODO (JF): When the deno console issue is resolved, this will be removed
    const console = Object.getPrototypeOf(globalThis).console;
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
}
