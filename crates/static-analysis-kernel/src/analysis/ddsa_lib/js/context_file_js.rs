// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use std::marker::PhantomData;

use deno_core::v8::HandleScope;
use deno_core::v8::{self, Handle};

use crate::analysis::ddsa_lib::common::{
    load_function, set_key_value, set_undefined, v8_interned, v8_string, Class, DDSAJsRuntimeError,
    Instance,
};
use crate::analysis::ddsa_lib::file_js::PackageImport;
use crate::rust_converter;

/// A [`v8::Global`] object created from the ES6 class `FileContextTerraform`.
#[derive(Debug)]
pub struct FileContextJavaScript<T> {
    v8_function: v8::Global<v8::Function>,
    // Cached keys
    s_js_imports_package: v8::Global<v8::String>,
    _pd: PhantomData<T>,
}

/// A function representing the ES6 class `PackageImport`.
#[derive(Debug)]
pub struct JSPackageImport<T> {
    class: v8::Global<v8::Function>,
    _pd: PhantomData<T>,
}

rust_converter!(
    (JSPackageImport<Class>, PackageImport),
    |&self, scope, value| {
        let name = v8_string(scope, &value.name).into();
        let imported_from = if let Some(imported_from) = &value.imported_from {
            v8_string(scope, imported_from).into()
        } else {
            v8::null(scope).into()
        };
        let imported_as = if let Some(imported_as) = &value.imported_as {
            v8_string(scope, imported_as).into()
        } else {
            v8::null(scope).into()
        };
        let args = [name, imported_from, imported_as];
        self.class
            .open(scope)
            .new_instance(scope, &args[..])
            .expect("class constructor should not throw")
            .into()
    }
);

impl FileContextJavaScript<Instance> {
    pub const FUNCTION_NAME: &'static str = "jsImportsPackage";

    /// Creates a new [`v8::Global`] object by loading [`Self::CLASS_NAME`] from the `scope` and creating an instance.
    pub fn try_new(scope: &mut HandleScope) -> Result<Self, DDSAJsRuntimeError> {
        let v8_function = load_function(scope, Self::FUNCTION_NAME)?;

        let s_js_imports_package = v8_interned(scope, Self::FUNCTION_NAME);
        let s_js_imports_package = v8::Global::new(scope, s_js_imports_package);
        Ok(Self {
            v8_function,
            s_js_imports_package,
            _pd: PhantomData,
        })
    }

    /// Provides a reference to the [`v8::Global`] `jsImportsPackage` function
    pub(crate) fn v8_function(&self) -> &v8::Global<v8::Function> {
        &self.v8_function
    }
}

impl JSPackageImport<Class> {
    pub const CLASS_NAME: &'static str = "PackageImport";

    /// Creates a new [`v8::Global`] object by loading [`Self::CLASS_NAME`] from the `scope`.
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
    use crate::analysis::ddsa_lib::{
        common::v8_uint,
        test_utils::{attach_as_global, cfg_test_runtime, js_class_eq, js_instance_eq},
    };

    #[test]
    fn js_properties_canary() {
        // PackageImport
        let instance_expected = &[
            // Variables
            "name",
            "importedFrom",
            "importedAs",
            // Methods
            "isAlias",
            "isModule",
        ];
        assert!(js_instance_eq(
            JSPackageImport::CLASS_NAME,
            instance_expected
        ));
        let class_expected = &[];
        assert!(js_class_eq(JSPackageImport::CLASS_NAME, class_expected));
    }
}
