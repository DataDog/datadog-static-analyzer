// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::analysis::ddsa_lib::bridge::{
    ContextBridge, QueryMatchBridge, TsNodeBridge, TsSymbolMapBridge, ViolationBridge,
};
use crate::analysis::ddsa_lib::common::{v8_interned, DDSAJsRuntimeError};
use crate::analysis::ddsa_lib::extension::ddsa_lib;
use deno_core::v8;
use std::cell::{RefCell, RefMut};
use std::rc::Rc;

const BRIDGE_CONTEXT: &str = "__RUST_BRIDGE__context";
const BRIDGE_QUERY_MATCH: &str = "__RUST_BRIDGE__query_match";
const BRIDGE_TS_NODE: &str = "__RUST_BRIDGE__ts_node";
const BRIDGE_TS_SYMBOL: &str = "__RUST_BRIDGE__ts_symbol_lookup";
const BRIDGE_VIOLATION: &str = "__RUST_BRIDGE__violation";

/// The Datadog Static Analyzer JavaScript runtime
pub struct JsRuntime {
    runtime: deno_core::JsRuntime,
    console: Rc<RefCell<JsConsole>>,
    bridge_context: Rc<RefCell<ContextBridge>>,
    bridge_query_match: QueryMatchBridge,
    bridge_ts_node: Rc<RefCell<TsNodeBridge>>,
    bridge_ts_symbol_map: Rc<TsSymbolMapBridge>,
    bridge_violation: ViolationBridge,
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
            ddsa_v8_ctx_true_global: ctx_true_global,
            s_bridge_ts_symbol_lookup,
        })
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
    use crate::analysis::ddsa_lib::common::{compile_script, v8_interned};
    use crate::analysis::ddsa_lib::test_utils::{js_all_props, try_execute};
    use crate::analysis::ddsa_lib::JsRuntime;
    use deno_core::v8;
    use std::collections::HashSet;

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
}
