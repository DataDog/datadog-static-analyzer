// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::analysis::ddsa_lib::common::{
    load_function, set_key_value, set_undefined, v8_interned, DDSAJsRuntimeError, Instance,
};
use crate::analysis::ddsa_lib::js::RuleContext;
use deno_core::v8;
use deno_core::v8::HandleScope;
use std::cell::RefCell;
use std::collections::HashMap;
use std::marker::PhantomData;

/// A [`v8::Global`] object created from the ES6 class `TsLanguageContext`.
#[derive(Debug)]
pub struct TsLanguageContext<T> {
    v8_object: v8::Global<v8::Object>,
    // Cached keys
    s_node_type: v8::Global<v8::String>,
    s_field: v8::Global<v8::String>,
    /// (See documentation on [`Instance`]).
    _pd: PhantomData<T>,
}

impl TsLanguageContext<Instance> {
    /// The name of the JavaScript class.
    pub const CLASS_NAME: &'static str = "TsLanguageContext";

    /// Creates a new [`v8::Global`] object by loading [`Self::CLASS_NAME`] from the `scope` and creating an instance.
    pub fn try_new(scope: &mut HandleScope) -> Result<Self, DDSAJsRuntimeError> {
        let js_class = load_function(scope, Self::CLASS_NAME)?;
        let js_class = js_class.open(scope);
        let v8_object = js_class
            .new_instance(scope, &[][..])
            .expect("class constructor should not throw");
        let v8_object = v8::Global::new(scope, v8_object);
        let s_node_type = v8_interned(scope, "nodeType");
        let s_node_type = v8::Global::new(scope, s_node_type);
        let s_field = v8_interned(scope, "field");
        let s_field = v8::Global::new(scope, s_field);
        Ok(Self {
            v8_object,
            s_node_type,
            s_field,
            _pd: PhantomData,
        })
    }

    /// Returns a local handle to the underlying [`v8::Global`] object.
    pub fn as_local<'s>(&self, scope: &mut HandleScope<'s>) -> v8::Local<'s, v8::Object> {
        v8::Local::new(scope, &self.v8_object)
    }

    /// Sets the [`v8::Map`]s containing the language's metadata.
    pub fn set_metadata(
        &self,
        scope: &mut HandleScope,
        node_type_map: Option<&v8::Global<v8::Map>>,
        child_field_map: Option<&v8::Global<v8::Map>>,
    ) {
        if let Some(v8_map) = node_type_map {
            set_key_value(&self.v8_object, scope, &self.s_node_type, |inner| {
                v8::Local::new(inner, v8_map).into()
            });
        } else {
            set_undefined(&self.v8_object, scope, &self.s_node_type);
        }
        if let Some(v8_map) = child_field_map {
            set_key_value(&self.v8_object, scope, &self.s_field, |inner| {
                v8::Local::new(inner, v8_map).into()
            });
        } else {
            set_undefined(&self.v8_object, scope, &self.s_field);
        }
    }

    /// Gets a local handle to the `v8::Map` for `s_field`.
    #[cfg(test)]
    pub fn get_prop_field<'s>(&self, scope: &mut HandleScope<'s>) -> v8::Local<'s, v8::Map> {
        let opened = self.v8_object.open(scope);
        let v8_key = v8::Local::new(scope, &self.s_field);
        let value = opened.get(scope, v8_key.into()).unwrap();
        value.try_into().unwrap()
    }

    /// Gets a local handle to the `v8::Map` for `s_node_type`.
    #[cfg(test)]
    pub fn get_prop_node_type<'s>(&self, scope: &mut HandleScope<'s>) -> v8::Local<'s, v8::Map> {
        let opened = self.v8_object.open(scope);
        let v8_key = v8::Local::new(scope, &self.s_node_type);
        let value = opened.get(scope, v8_key.into()).unwrap();
        value.try_into().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use crate::analysis::ddsa_lib::js::TsLanguageContext;
    use crate::analysis::ddsa_lib::test_utils::{js_class_eq, js_instance_eq};

    #[test]
    fn js_properties_canary() {
        let instance_exp = &[
            // Variables
            "nodeType", "field",
        ];
        assert!(js_instance_eq(TsLanguageContext::CLASS_NAME, instance_exp));
        let class_expected = &[];
        assert!(js_class_eq(TsLanguageContext::CLASS_NAME, class_expected));
    }
}
