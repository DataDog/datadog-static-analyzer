// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::analysis::ddsa_lib::common::{
    load_function, set_key_value, set_undefined, v8_interned, v8_string, DDSAJsRuntimeError,
    Instance,
};
use deno_core::v8;
use deno_core::v8::HandleScope;
use std::marker::PhantomData;

/// A [`v8::Global`] object created from the ES6 class `FileContext`.
#[derive(Debug)]
pub struct FileContext<T> {
    v8_object: v8::Global<v8::Object>,
    _pd: PhantomData<T>,
}

impl FileContext<Instance> {
    /// The name of the JavaScript class.
    pub const CLASS_NAME: &'static str = "FileContext";

    /// Creates a new [`v8::Global`] object by loading [`Self::CLASS_NAME`] from the `scope` and creating an instance.
    pub fn try_new(scope: &mut HandleScope) -> Result<Self, DDSAJsRuntimeError> {
        let js_class = load_function(scope, Self::CLASS_NAME)?;
        let js_class = js_class.open(scope);
        let v8_object = js_class
            .new_instance(scope, &[])
            .expect("class constructor should not throw");
        let v8_object = v8::Global::new(scope, v8_object);
        let _pd = PhantomData;
        Ok(Self { v8_object, _pd })
    }

    /// Returns a local handle to the underlying [`v8::Global`] object.
    pub fn as_local<'s>(&self, scope: &mut HandleScope<'s>) -> v8::Local<'s, v8::Object> {
        v8::Local::new(scope, &self.v8_object)
    }

    /// Provides a reference to the [`v8::Global`] class instance object
    pub(crate) fn v8_object(&self) -> &v8::Global<v8::Object> {
        &self.v8_object
    }
}

#[cfg(test)]
mod tests {
    use crate::analysis::ddsa_lib::js::FileContext;
    use crate::analysis::ddsa_lib::test_utils::{js_class_eq, js_instance_eq};

    #[test]
    fn js_properties_canary() {
        let instance_expected = &[
            // Variables
        ];
        assert!(js_instance_eq(FileContext::CLASS_NAME, instance_expected));
        let class_expected = &[];
        assert!(js_class_eq(FileContext::CLASS_NAME, class_expected));
    }
}