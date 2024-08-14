// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::analysis::ddsa_lib::common::{v8_interned, v8_uint, NodeId};
use deno_core::v8;
use deno_core::v8::HandleScope;

/// A [`v8::Global`] template for creating `SingleCapture` v8 objects.
#[derive(Debug)]
pub(crate) struct SingleCaptureTemplate {
    template: v8::Global<v8::ObjectTemplate>,
    // Cached keys
    s_name: v8::Global<v8::String>,
    s_node_id: v8::Global<v8::String>,
}

impl SingleCaptureTemplate {
    pub fn new(scope: &mut HandleScope) -> Self {
        let s_name = v8_interned(scope, "name");
        let s_node_id = v8_interned(scope, "nodeId");
        let undefined = v8::undefined(scope);
        let zero_smi = v8_uint(scope, 0);

        let template = v8::ObjectTemplate::new(scope);
        template.set(s_name.into(), undefined.into());
        template.set(s_node_id.into(), zero_smi.into());
        let template = v8::Global::new(scope, template);

        let s_name = v8::Global::new(scope, s_name);
        let s_node_id = v8::Global::new(scope, s_node_id);

        Self {
            template,
            s_name,
            s_node_id,
        }
    }

    /// Creates a new local [`v8::Object`] for a `SingleCapture`.
    pub fn new_instance<'s>(
        &self,
        scope: &mut HandleScope<'s>,
        name: &str,
        node_id: NodeId,
    ) -> v8::Local<'s, v8::Object> {
        let capture = self
            .template
            .open(scope)
            .new_instance(scope)
            .expect("v8 object should be able to be created");
        let key = v8::Local::new(scope, &self.s_name);
        let name = v8_interned(scope, name);
        capture.set(scope, key.into(), name.into());
        let key = v8::Local::new(scope, &self.s_node_id);
        let id = v8_uint(scope, node_id);
        capture.set(scope, key.into(), id.into());
        capture
    }
}

/// A [`v8::Global`] template for creating `MultiCapture` v8 objects.
#[derive(Debug)]
pub(crate) struct MultiCaptureTemplate {
    template: v8::Global<v8::ObjectTemplate>,
    // Cached keys
    s_name: v8::Global<v8::String>,
    s_node_ids: v8::Global<v8::String>,
}

impl MultiCaptureTemplate {
    pub fn new(scope: &mut HandleScope) -> Self {
        let s_name = v8_interned(scope, "name");
        let s_node_ids = v8_interned(scope, "nodeIds");
        let undefined = v8::undefined(scope);

        let template = v8::ObjectTemplate::new(scope);
        template.set(s_name.into(), undefined.into());
        template.set(s_node_ids.into(), undefined.into());
        let template = v8::Global::new(scope, template);

        let s_name = v8::Global::new(scope, s_name);
        let s_node_ids = v8::Global::new(scope, s_node_ids);

        Self {
            template,
            s_name,
            s_node_ids,
        }
    }

    /// Creates a new local [`v8::Object`] for a `MultiCapture`.
    pub fn new_instance<'s>(
        &self,
        scope: &mut HandleScope<'s>,
        name: &str,
        node_ids: &[NodeId],
    ) -> v8::Local<'s, v8::Object> {
        let capture = self
            .template
            .open(scope)
            .new_instance(scope)
            .expect("v8 object should be able to be created");
        let key = v8::Local::new(scope, &self.s_name);
        let name = v8_interned(scope, name);
        capture.set(scope, key.into(), name.into());

        let key = v8::Local::new(scope, &self.s_node_ids);
        let ids_buf = v8::ArrayBuffer::new(scope, 4 * node_ids.len());
        let ids_array = v8::Uint32Array::new(scope, ids_buf, 0, node_ids.len())
            .expect("v8 Uint32Array should be able to be created");
        for (i, node_id) in node_ids.iter().enumerate() {
            let id = v8_uint(scope, *node_id);
            ids_array.set_index(scope, i as u32, id.into());
        }
        capture.set(scope, key.into(), ids_array.into());
        capture
    }
}

#[cfg(test)]
mod tests {
    use crate::analysis::ddsa_lib::js::{MultiCaptureTemplate, SingleCaptureTemplate};
    use crate::analysis::ddsa_lib::test_utils::{attach_as_global, cfg_test_runtime, try_execute};

    // These objects are created entirely in v8, so the property canary tests are implemented
    // slightly differently than in other files where we use `js_instance_eq`.

    /// Verifies the object shape of a `SingleCapture`.
    #[test]
    fn single_capture_js_properties_canary() {
        let mut runtime = cfg_test_runtime();
        let scope = &mut runtime.handle_scope();
        let template = SingleCaptureTemplate::new(scope);
        let capture = template.new_instance(scope, "alpha", 16);
        attach_as_global(scope, capture, "CAPTURE");

        let code = r#"
assert(Object.keys(CAPTURE).length === 2, "must be exactly 2 properties");
assert(CAPTURE.name === "alpha", "name was incorrect");
assert(CAPTURE.nodeId === 16, "nodeId was incorrect");
"#;
        let result = try_execute(scope, code).map(|v| v.to_rust_string_lossy(scope));
        assert_eq!(result, Ok("undefined".to_string()));
    }

    /// Verifies the object shape of a `MultiCapture`.
    #[test]
    fn multi_capture_js_properties_canary() {
        let mut runtime = cfg_test_runtime();
        let scope = &mut runtime.handle_scope();
        let template = MultiCaptureTemplate::new(scope);
        let capture = template.new_instance(scope, "bravo", &[16, 32, 48]);
        attach_as_global(scope, capture, "CAPTURE");

        let code = r#"
assert(Object.keys(CAPTURE).length === 2, "must be exactly 2 properties");
assert(CAPTURE.name === "bravo", "name was incorrect");
assert(CAPTURE.nodeIds instanceof Uint32Array, "nodeIds had wrong type");
assert(CAPTURE.nodeIds.join(",") === "16,32,48", "nodeIds were incorrect");
"#;
        let result = try_execute(scope, code).map(|v| v.to_rust_string_lossy(scope));
        assert_eq!(result, Ok("undefined".to_string()));

        // Single capture within an array should still be an array
        let capture = template.new_instance(scope, "bravo", &[16]);
        attach_as_global(scope, capture, "CAPTURE");
        let code = r#"
assert(CAPTURE.nodeIds instanceof Uint32Array, "nodeIds had wrong type");
assert(CAPTURE.nodeIds.join(",") === "16", "nodeIds were incorrect");
"#;
        let result = try_execute(scope, code).map(|v| v.to_rust_string_lossy(scope));
        assert_eq!(result, Ok("undefined".to_string()));
    }
}
