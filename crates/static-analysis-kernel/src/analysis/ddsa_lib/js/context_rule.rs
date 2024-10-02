// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::analysis::ddsa_lib::common::{
    load_function, set_key_value, set_undefined, v8_interned, DDSAJsRuntimeError, Instance,
};
use deno_core::v8;
use deno_core::v8::HandleScope;
use std::marker::PhantomData;

/// A [`v8::Global`] object created from the ES6 class `RuleContext`.
#[derive(Debug)]
pub struct RuleContext<T> {
    v8_object: v8::Global<v8::Object>,
    // Cached keys
    s_arguments: v8::Global<v8::String>,
    /// (See documentation on [`Instance`]).
    _pd: PhantomData<T>,
}

impl RuleContext<Instance> {
    /// The name of the JavaScript class.
    pub const CLASS_NAME: &'static str = "RuleContext";

    /// Creates a new [`v8::Global`] object by loading [`Self::CLASS_NAME`] from the `scope` and creating an instance.
    pub fn try_new(scope: &mut HandleScope) -> Result<Self, DDSAJsRuntimeError> {
        let js_class = load_function(scope, Self::CLASS_NAME)?;
        let js_class = js_class.open(scope);
        let args = [v8::undefined(scope).into()];
        let v8_object = js_class
            .new_instance(scope, &args[..])
            .expect("class constructor should not throw");
        let v8_object = v8::Global::new(scope, v8_object);
        let s_arguments = v8_interned(scope, "_arguments");
        let s_arguments = v8::Global::new(scope, s_arguments);
        Ok(Self {
            v8_object,
            s_arguments,
            _pd: PhantomData,
        })
    }

    /// Returns a local handle to the underlying [`v8::Global`] object.
    pub fn as_local<'s>(&self, scope: &mut HandleScope<'s>) -> v8::Local<'s, v8::Object> {
        v8::Local::new(scope, &self.v8_object)
    }

    /// Sets the [`v8::Map`] containing argument names and argument values.
    pub fn set_arguments_map(
        &self,
        scope: &mut HandleScope,
        arguments_map: Option<&v8::Global<v8::Map>>,
    ) {
        if let Some(v8_map) = arguments_map {
            set_key_value(&self.v8_object, scope, &self.s_arguments, |inner| {
                v8::Local::new(inner, v8_map).into()
            });
        } else {
            set_undefined(&self.v8_object, scope, &self.s_arguments);
        }
    }

    /// Returns a local handle to the [`v8::Global`] map, if present.
    pub fn v8_arguments_map<'s>(
        &self,
        scope: &mut HandleScope<'s>,
    ) -> Option<v8::Local<'s, v8::Map>> {
        let v8_key = v8::Local::new(scope, &self.s_arguments);
        let v8_args = self.v8_object.open(scope).get(scope, v8_key.into());
        v8_args.and_then(|value| {
            if value.is_undefined() {
                None
            } else {
                let cast: Option<v8::Local<v8::Map>> = value.try_into().ok();
                cast
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::analysis::ddsa_lib::js::context_rule::RuleContext;
    use crate::analysis::ddsa_lib::test_utils::{js_class_eq, js_instance_eq};

    #[test]
    fn js_properties_canary() {
        let instance_expected = &[
            // Variables
            "_arguments",
            // Methods
            "getArgument",
        ];
        assert!(js_instance_eq(RuleContext::CLASS_NAME, instance_expected));
        let class_expected = &[];
        assert!(js_class_eq(RuleContext::CLASS_NAME, class_expected));
    }
}
