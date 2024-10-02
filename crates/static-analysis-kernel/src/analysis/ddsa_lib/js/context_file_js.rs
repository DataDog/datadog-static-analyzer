// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use std::marker::PhantomData;

use deno_core::v8::{self, Handle, HandleScope};

use crate::analysis::ddsa_lib::common::{
    load_function, set_key_value, set_undefined, v8_interned, v8_string, Class, DDSAJsRuntimeError,
    Instance,
};
use crate::analysis::ddsa_lib::file_js::PackageImport;
use crate::rust_converter;

/// A [`v8::Global`] object created from the ES6 class `FileContextTerraform`.
#[derive(Debug)]
pub struct FileContextJavaScript<T> {
    v8_object: v8::Global<v8::Object>,
    // Cached keys
    s_imports: v8::Global<v8::String>,
    /// (See documentation on [`Instance`]).
    _pd: PhantomData<T>,
}

/// A function representing the ES6 class `PackageImport`.
#[derive(Debug)]
pub struct JSPackageImport<T> {
    class: v8::Global<v8::Function>,
    /// (See documentation on [`Class`]).
    _pd: PhantomData<T>,
}

rust_converter!(
    (JSPackageImport<Class>, PackageImport),
    |&self, scope, value| {
        let name = v8_string(scope, &value.name).into();
        let imported_from = if let Some(imported_from) = &value.imported_from {
            v8_string(scope, imported_from).into()
        } else {
            v8::undefined(scope).into()
        };
        let args = [name, imported_from];
        self.class
            .open(scope)
            .new_instance(scope, &args[..])
            .expect("class constructor should not throw")
            .into()
    }
);

impl FileContextJavaScript<Instance> {
    pub const CLASS_NAME: &'static str = "FileContextJavaScript";

    /// Creates a new [`v8::Global`] object by loading [`Self::CLASS_NAME`] from the `scope` and creating an instance.
    pub fn try_new(scope: &mut HandleScope) -> Result<Self, DDSAJsRuntimeError> {
        let js_class = load_function(scope, Self::CLASS_NAME)?;
        let js_class = js_class.open(scope);
        let args = [v8::undefined(scope).into()];
        let v8_object = js_class
            .new_instance(scope, &args[..])
            .expect("class constructor should not throw");
        let v8_object = v8::Global::new(scope, v8_object);
        let s_imports = v8_interned(scope, "imports");
        let s_imports = v8::Global::new(scope, s_imports);
        Ok(Self {
            v8_object,
            s_imports,
            _pd: PhantomData,
        })
    }

    /// Assigns either the provided [`v8::Global`] array to the JavaScript object's [`FileContextJavaScript::s_imports`] key,
    /// or `undefined` if no array is provided.
    pub fn set_imports_array(
        &self,
        scope: &mut HandleScope,
        array: Option<&v8::Global<v8::Array>>,
    ) {
        if let Some(v8_map) = array {
            set_key_value(&self.v8_object, scope, &self.s_imports, |inner| {
                v8::Local::new(inner, v8_map).into()
            });
        } else {
            set_undefined(&self.v8_object, scope, &self.s_imports);
        }
    }

    /// Provides a reference to the [`v8::Global`] class instance object
    pub(crate) fn v8_object(&self) -> &v8::Global<v8::Object> {
        &self.v8_object
    }
}

impl JSPackageImport<Class> {
    pub const CLASS_NAME: &'static str = "PackageImport";

    /// Creates a new [`v8::Global`] function by loading [`Self::CLASS_NAME`] from the `scope`.
    pub fn try_new(scope: &mut HandleScope) -> Result<Self, DDSAJsRuntimeError> {
        let js_class = load_function(scope, Self::CLASS_NAME)?;
        Ok(Self {
            class: js_class,
            _pd: PhantomData,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::ddsa_lib::common::v8_uint;
    use crate::analysis::ddsa_lib::test_utils::{
        attach_as_global, cfg_test_runtime, js_class_eq, js_instance_eq,
    };

    #[test]
    fn js_properties_canary() {
        // PackageImport
        let instance_expected = &[
            // Variables
            "name",
            "importedFrom",
            // Methods
            "isModule",
        ];
        assert!(js_instance_eq(
            JSPackageImport::CLASS_NAME,
            instance_expected
        ));
        let class_expected = &[];
        assert!(js_class_eq(JSPackageImport::CLASS_NAME, class_expected));

        // FileContextJavaScript
        let instance_expected = &[
            // Variables
            "imports",
            // Methods
            "importsPackage",
        ];
        assert!(js_instance_eq(
            FileContextJavaScript::CLASS_NAME,
            instance_expected
        ));
        let class_expected = &[];
        assert!(js_class_eq(
            FileContextJavaScript::CLASS_NAME,
            class_expected
        ));
    }
}
