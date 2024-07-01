// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::analysis::ddsa_lib::common::{
    load_function, set_key_value, set_undefined, v8_interned, v8_string, DDSAJsRuntimeError,
    Instance,
};
use crate::analysis::ddsa_lib::js;
use deno_core::v8;
use deno_core::v8::HandleScope;
use std::marker::PhantomData;

/// A [`v8::Global`] object created from the ES6 class `RootContext`.
#[derive(Debug)]
pub struct RootContext<T> {
    v8_object: v8::Global<v8::Object>,
    // Cached keys
    s_file_ctx: v8::Global<v8::String>,
    s_rule_ctx: v8::Global<v8::String>,
    s_filename: v8::Global<v8::String>,
    s_file_contents: v8::Global<v8::String>,
    _pd: PhantomData<T>,
}

impl RootContext<Instance> {
    /// The name of the JavaScript class.
    pub const CLASS_NAME: &'static str = "RootContext";

    /// Creates a new [`v8::Global`] object by loading [`Self::CLASS_NAME`] from the `scope` and creating an instance.
    pub fn try_new(scope: &mut HandleScope) -> Result<Self, DDSAJsRuntimeError> {
        let js_class = load_function(scope, Self::CLASS_NAME)?;
        let js_class = js_class.open(scope);
        let undefined = v8::undefined(scope);
        let args = [undefined.into(), undefined.into()];
        let v8_object = js_class
            .new_instance(scope, &args[..])
            .expect("class constructor should not throw");
        let v8_object = v8::Global::new(scope, v8_object);
        let s_file_ctx = v8_interned(scope, "fileCtx");
        let s_file_ctx = v8::Global::new(scope, s_file_ctx);
        let s_rule_ctx = v8_interned(scope, "ruleCtx");
        let s_rule_ctx = v8::Global::new(scope, s_rule_ctx);
        let s_filename = v8_interned(scope, "__js_cachedFilename");
        let s_filename = v8::Global::new(scope, s_filename);
        let s_file_contents = v8_interned(scope, "__js_cachedFileContents");
        let s_file_contents = v8::Global::new(scope, s_file_contents);
        Ok(Self {
            v8_object,
            s_file_ctx,
            s_rule_ctx,
            s_filename,
            s_file_contents,
            _pd: PhantomData,
        })
    }

    /// Returns a local handle to the underlying [`v8::Global`] object.
    pub fn as_local<'s>(&self, scope: &mut HandleScope<'s>) -> v8::Local<'s, v8::Object> {
        v8::Local::new(scope, &self.v8_object)
    }

    /// Sets the rule context.
    pub fn set_rule_ctx(
        &self,
        scope: &mut HandleScope,
        rule_ctx: Option<&js::RuleContext<Instance>>,
    ) {
        if let Some(rule_ctx) = rule_ctx {
            set_key_value(&self.v8_object, scope, &self.s_rule_ctx, |inner| {
                rule_ctx.as_local(inner).into()
            });
        } else {
            set_undefined(&self.v8_object, scope, &self.s_rule_ctx);
        }
    }

    /// Sets the file context.
    pub fn set_file_ctx(
        &self,
        scope: &mut HandleScope,
        file_ctx: Option<&js::FileContext<Instance>>,
    ) {
        if let Some(file_ctx) = file_ctx {
            set_key_value(&self.v8_object, scope, &self.s_file_ctx, |inner| {
                file_ctx.as_local(inner).into()
            });
        } else {
            set_undefined(&self.v8_object, scope, &self.s_file_ctx);
        }
    }

    /// Sets the filename cache in the context.
    pub fn set_filename_cache(&self, scope: &mut HandleScope, filename: Option<&str>) {
        if let Some(filename) = filename {
            set_key_value(&self.v8_object, scope, &self.s_filename, |inner| {
                v8_string(inner, filename).into()
            });
        } else {
            set_undefined(&self.v8_object, scope, &self.s_filename);
        }
    }

    /// Gets the value of the filename cache.
    #[cfg(test)]
    pub fn get_filename_cache(&self, scope: &mut HandleScope) -> Option<String> {
        self.get_cache(scope, &self.s_filename)
    }

    /// Gets the value of the file contents cache.
    #[cfg(test)]
    pub fn get_file_contents_cache(&self, scope: &mut HandleScope) -> Option<String> {
        self.get_cache(scope, &self.s_file_contents)
    }

    /// Sets the file contents cache in the context.
    pub fn set_file_contents_cache(&self, scope: &mut HandleScope, file_contents: Option<&str>) {
        if let Some(file_contents) = file_contents {
            set_key_value(&self.v8_object, scope, &self.s_file_contents, |inner| {
                v8_string(inner, file_contents).into()
            });
        } else {
            set_undefined(&self.v8_object, scope, &self.s_file_contents);
        }
    }

    #[cfg(test)]
    fn get_cache(&self, scope: &mut HandleScope, key: &v8::Global<v8::String>) -> Option<String> {
        let v8_key = v8::Local::new(scope, key);
        let v8_value = self.v8_object.open(scope).get(scope, v8_key.into());
        let v8_value = v8_value.unwrap();
        if v8_value.is_string() {
            Some(v8_value.to_rust_string_lossy(scope))
        } else if v8_value.is_undefined() {
            None
        } else {
            panic!("unexpected v8 type")
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::analysis::ddsa_lib::bridge::ContextBridge;
    use crate::analysis::ddsa_lib::common::v8_string;
    use crate::analysis::ddsa_lib::js::RootContext;
    use crate::analysis::ddsa_lib::test_utils::{
        attach_as_global, cfg_test_runtime, js_class_eq, js_instance_eq, parse_code, try_execute,
    };
    use crate::model::common::Language;
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::sync::Arc;

    /// Constructs a `ContextBridge` and attaches it to `globalThis` with the given name
    fn setup_bridge(runtime: &mut deno_core::JsRuntime, name: &str) -> Rc<RefCell<ContextBridge>> {
        let bridge = ContextBridge::try_new(&mut runtime.handle_scope()).unwrap();
        let bridge = Rc::new(RefCell::new(bridge));
        runtime.op_state().borrow_mut().put(Rc::clone(&bridge));
        let scope = &mut runtime.handle_scope();
        let v8_bridge = bridge.borrow().as_local(scope);
        attach_as_global(scope, v8_bridge, name);
        bridge
    }

    #[test]
    fn js_properties_canary() {
        let instance_expected = &[
            // Variables
            "__js_cachedFilename",
            "__js_cachedFileContents",
            "fileCtx",
            "ruleCtx",
            // Methods
            "fileContents",
            "filename",
        ];
        assert!(js_instance_eq(RootContext::CLASS_NAME, instance_expected));
        let class_expected = &[];
        assert!(js_class_eq(RootContext::CLASS_NAME, class_expected));
    }

    /// File contents can be retrieved and cached.
    /// Filename can be retrieved and cached.
    #[rustfmt::skip]
    #[test]
    fn get_file_info() {
        let file_contents = "\
// File
// Contents
const sampleFileContents = 0 + 1 + 2;
";
        let file_contents = Arc::<str>::from(file_contents);
        let file_name = Arc::<str>::from("file_name.js");

        let mut runtime = cfg_test_runtime();
        let bridge = setup_bridge(&mut runtime, "ROOT");
        let tree = Arc::new(parse_code(&file_contents, Language::JavaScript));
        let scope = &mut runtime.handle_scope();
        bridge
            .borrow_mut()
            .set_root_context(scope, &tree, &file_contents, &file_name);
        let v8_bridge = bridge.borrow().as_local(scope);
        for (cache_key, js_code, expected) in [
            ("__js_cachedFileContents", "ROOT.fileContents;", &file_contents),
            ("__js_cachedFilename", "ROOT.filename;", &file_name),
        ] {
            let cache_key = v8_string(scope, cache_key);
            let cache_before = v8_bridge.get(scope, cache_key.into()).unwrap();
            assert!(cache_before.is_undefined());
            let res = try_execute(scope, js_code).unwrap();
            assert_eq!(res.to_rust_string_lossy(scope), expected.as_ref());
            let cache_after = v8_bridge.get(scope, cache_key.into()).unwrap();
            assert!(cache_after.is_string());
        }
    }
}
