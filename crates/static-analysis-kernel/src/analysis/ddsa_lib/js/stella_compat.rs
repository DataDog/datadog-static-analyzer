// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::analysis::ddsa_lib::common::{load_function, DDSAJsRuntimeError, Instance};
use crate::analysis::ddsa_lib::js::{MultiCaptureTemplate, SingleCaptureTemplate};
use deno_core::v8;
use deno_core::v8::{Handle, HandleScope, IntegrityLevel};
use std::marker::PhantomData;

/// A [`v8::Global`] object created from the ES6 class `VisitArgFilenameCompat`.
#[derive(Debug)]
pub struct VisitArgFilenameCompat<T> {
    v8_object: v8::Global<v8::Object>,
    _pd: PhantomData<T>,
}

impl VisitArgFilenameCompat<Instance> {
    pub const CLASS_NAME: &'static str = "VisitArgFilenameCompat";

    /// Creates a new [`v8::Global`] function by loading [`Self::CLASS_NAME`] from the `scope`.
    pub fn try_new(scope: &mut HandleScope) -> Result<Self, DDSAJsRuntimeError> {
        let js_class = load_function(scope, Self::CLASS_NAME)?;
        let js_class = js_class.open(scope);
        let v8_object = js_class
            .new_instance(scope, &[])
            .expect("class constructor should not throw");
        v8_object.set_integrity_level(scope, IntegrityLevel::Sealed);
        let v8_object = v8::Global::new(scope, v8_object);
        Ok(Self {
            v8_object,
            _pd: PhantomData,
        })
    }

    /// Returns a local handle to the underlying [`v8::Global`] object.
    pub fn as_local<'s>(&self, scope: &mut HandleScope<'s>) -> v8::Local<'s, v8::Object> {
        v8::Local::new(scope, &self.v8_object)
    }
}

/// A function representing the ES6 class `VisitArgCodeCompat`.
#[derive(Debug)]
pub struct VisitArgCodeCompat<T> {
    v8_object: v8::Global<v8::Object>,
    _pd: PhantomData<T>,
}

impl VisitArgCodeCompat<Instance> {
    pub const CLASS_NAME: &'static str = "VisitArgCodeCompat";

    /// Creates a new [`v8::Global`] function by loading [`Self::CLASS_NAME`] from the `scope`.
    pub fn try_new(scope: &mut HandleScope) -> Result<Self, DDSAJsRuntimeError> {
        let js_class = load_function(scope, Self::CLASS_NAME)?;
        let js_class = js_class.open(scope);
        let v8_object = js_class
            .new_instance(scope, &[])
            .expect("class constructor should not throw");
        v8_object.set_integrity_level(scope, IntegrityLevel::Sealed);
        let v8_object = v8::Global::new(scope, v8_object);
        Ok(Self {
            v8_object,
            _pd: PhantomData,
        })
    }

    /// Returns a local handle to the underlying [`v8::Global`] object.
    pub fn as_local<'s>(&self, scope: &mut HandleScope<'s>) -> v8::Local<'s, v8::Object> {
        v8::Local::new(scope, &self.v8_object)
    }
}

#[cfg(test)]
mod tests {
    use crate::analysis::ddsa_lib::js::stella_compat::{
        VisitArgCodeCompat, VisitArgFilenameCompat,
    };
    use crate::analysis::ddsa_lib::test_utils::{
        attach_as_global, cfg_test_runtime, js_class_eq, js_instance_eq, make_stub_root_context,
        try_execute,
    };
    use deno_core::v8;

    const CTX_FILE_CONTENTS: &str = "\
thisStringRepresents('The file contents');\
";
    const CTX_FILENAME: &str = "filename.js";

    #[test]
    fn filename_js_properties_canary() {
        // The class is a thin wrapper around a Proxy which targets an object with a single property.
        let expected = &["inner"];
        assert!(js_instance_eq(VisitArgFilenameCompat::CLASS_NAME, expected));
        assert!(js_class_eq(VisitArgFilenameCompat::CLASS_NAME, &[]));
    }

    #[test]
    fn code_js_properties_canary() {
        // The class is a thin wrapper around a Proxy which targets an object with a single property.
        let expected = &["inner"];
        assert!(js_instance_eq(VisitArgCodeCompat::CLASS_NAME, expected));
        assert!(js_class_eq(VisitArgCodeCompat::CLASS_NAME, &[]));
    }

    /// Tests that the class instance behaves like a `String` object, but accessing it returns the filename.
    #[test]
    fn filename_proxy() {
        let mut runtime = cfg_test_runtime();
        let scope = &mut runtime.handle_scope();

        let stub_root_context = make_stub_root_context(scope, &[], CTX_FILENAME, "", None);
        attach_as_global(scope, stub_root_context, "__RUST_BRIDGE__context");

        let v8_filename_proxy = VisitArgFilenameCompat::try_new(scope).unwrap();
        let v8_filename_proxy = v8::Local::new(scope, v8_filename_proxy.v8_object);
        attach_as_global(scope, v8_filename_proxy, "__FILENAME_PROXY__");

        let code = r#"
assert(typeof __FILENAME_PROXY__ === "object", "value should be a Proxy object")
assert(__FILENAME_PROXY__ == "filename.js", "valueOf trap doesn't work");
assert(__FILENAME_PROXY__.length === 11, "property access doesn't work");
assert(__FILENAME_PROXY__.includes("name"), "method invocation doesn't work");
        "#;
        let value = try_execute(scope, code).unwrap();
        assert_eq!(value.to_rust_string_lossy(scope), "undefined");
    }

    /// Tests that the class instance behaves like a `String` object, but accessing it returns the code.
    #[test]
    fn file_contents_proxy() {
        let mut runtime = cfg_test_runtime();
        let scope = &mut runtime.handle_scope();

        let stub_root_context = make_stub_root_context(scope, &[], "", CTX_FILE_CONTENTS, None);
        attach_as_global(scope, stub_root_context, "__RUST_BRIDGE__context");

        let v8_filename_proxy = VisitArgCodeCompat::try_new(scope).unwrap();
        let v8_filename_proxy = v8::Local::new(scope, v8_filename_proxy.v8_object);
        attach_as_global(scope, v8_filename_proxy, "__FILE_CONTENTS_PROXY__");

        let code = r#"
assert(typeof __FILE_CONTENTS_PROXY__ === "object", "value should be a Proxy object")
assert(__FILE_CONTENTS_PROXY__ == "thisStringRepresents('The file contents');", "valueOf trap doesn't work");
assert(__FILE_CONTENTS_PROXY__.length === 42, "property access doesn't work");
assert(__FILE_CONTENTS_PROXY__.includes("contents"), "method invocation doesn't work");
        "#;
        let value = try_execute(scope, code).unwrap();
        assert_eq!(value.to_rust_string_lossy(scope), "undefined");
    }
}
