// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::analysis::ddsa_lib::common::{DDSAJsRuntimeError, Instance};
use crate::analysis::ddsa_lib::js;
use crate::analysis::ddsa_lib::js::ViolationConverter;
use crate::analysis::ddsa_lib::v8_ds::SyncedV8Array;
use deno_core::v8;
use deno_core::v8::HandleScope;

/// A stateful bridge pulling a collection of [`js::Violation`] from v8.
pub struct ViolationBridge(SyncedV8Array<js::Violation<Instance>, ViolationConverter>);

impl ViolationBridge {
    /// Creates a new, empty `ViolationBridge`.
    pub fn new(scope: &mut HandleScope) -> Self {
        let converter = ViolationConverter::new();
        let array = v8::Array::new(scope, 0);
        let array = v8::Global::new(scope, array);
        let synced = SyncedV8Array::with_capacity(converter, scope, array, 32);
        Self(synced)
    }

    /// Drains all data from the bridge, returning a list of [`Violation`].
    ///
    /// Existing `ViolationInstance` objects will be released to the v8 garbage collector.
    pub fn drain_collect(
        &mut self,
        scope: &mut HandleScope,
    ) -> Result<Vec<js::Violation<Instance>>, DDSAJsRuntimeError> {
        let res = self.0.drain_collect(scope);
        if res.is_err() {
            self.0.clear(scope)
        }
        res
    }

    /// Clears all data from bridge.
    pub fn clear(&mut self, scope: &mut HandleScope) {
        self.0.clear(scope);
    }

    /// Provides a local handle to the underlying [`v8::Global`] array powering the bridge.
    pub fn as_local<'s>(&self, scope: &mut HandleScope<'s>) -> v8::Local<'s, v8::Array> {
        self.0.as_local(scope)
    }
}

#[cfg(test)]
mod tests {
    use crate::analysis::ddsa_lib::bridge::violation::ViolationBridge;
    use crate::analysis::ddsa_lib::common::DDSAJsRuntimeError;
    use crate::analysis::ddsa_lib::test_utils::{attach_as_global, cfg_test_runtime, try_execute};
    use deno_core::JsRuntime;

    /// Sets up a bridge, binding it as a global JavaScript variable with name `global_name`.
    fn setup_bridge(global_name: &str) -> (JsRuntime, ViolationBridge) {
        let mut runtime = cfg_test_runtime();
        let v_bridge = {
            let scope = &mut runtime.handle_scope();
            let v_bridge = ViolationBridge::new(scope);
            let v8_v_bridge = v_bridge.as_local(scope);
            attach_as_global(scope, v8_v_bridge, global_name);
            v_bridge
        };
        (runtime, v_bridge)
    }

    /// Tests the statefulness of the bridge, and that it can be cleared between executions.
    #[test]
    fn violations_bridge_drains() {
        let (mut runtime, mut v_bridge) = setup_bridge("VIOLATIONS");
        let scope = &mut runtime.handle_scope();
        let v8_v_bridge = v_bridge.as_local(scope);
        assert_eq!(v8_v_bridge.length(), 0);

        let violations = v_bridge.drain_collect(scope).unwrap();
        assert!(violations.is_empty());

        let code = r#"
const v = Violation.new(8, 42, 8, 53, "Message describing the violation");
const e = Edit.newAdd(5, 0, "xyz");
const f = Fix.new("Message describing the fix", [e]);
v.addFix(f);
VIOLATIONS.push(v);
"#;
        try_execute(scope, code).unwrap();
        assert_eq!(v8_v_bridge.length(), 1);

        let violations = v_bridge.drain_collect(scope).unwrap();
        assert_eq!(v8_v_bridge.length(), 0);
        assert_eq!(violations.len(), 1);
    }

    /// Tests that the bridge is cleared when `drain_collect` is called, even if there were deserialization errors.
    #[test]
    fn violations_bridge_invalid_obj() {
        let (mut runtime, mut v_bridge) = setup_bridge("VIOLATIONS");
        let scope = &mut runtime.handle_scope();
        let v8_v_bridge = v_bridge.as_local(scope);
        assert_eq!(v8_v_bridge.length(), 0);

        let code = r#"
const valid = Violation.new(16, 84, 16, 106, "abcdef");
const invalid = Violation.new(8, 42, 8, 53, "abcdef");
delete invalid.startCol;
VIOLATIONS.push(valid, invalid);
"#;
        try_execute(scope, code).unwrap();
        assert_eq!(v8_v_bridge.length(), 2);

        let res = v_bridge.drain_collect(scope);
        let DDSAJsRuntimeError::VariableNotFound { name: missing } = res.unwrap_err() else {
            panic!("result should've been Err(VariableNotFound)")
        };
        assert_eq!(missing, "startCol");
        assert_eq!(v8_v_bridge.length(), 0);
    }
}
