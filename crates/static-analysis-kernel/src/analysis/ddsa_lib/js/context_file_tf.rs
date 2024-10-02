// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use std::marker::PhantomData;

use deno_core::v8::{self, HandleScope};

use crate::analysis::ddsa_lib::common::{
    load_function, set_key_value, set_undefined, v8_interned, v8_string, Class, DDSAJsRuntimeError,
    Instance,
};
use crate::analysis::ddsa_lib::file_tf::Resource;
use crate::rust_converter;

/// A [`v8::Global`] object created from the ES6 class `FileContextTerraform`.
#[derive(Debug)]
pub struct FileContextTerraform<T> {
    v8_object: v8::Global<v8::Object>,
    // Cached keys
    s_resource_map: v8::Global<v8::String>,
    /// (See documentation on [`Class`]).
    _pd: PhantomData<T>,
}

/// A function representing the ES6 class `TerraformResource`.
#[derive(Debug)]
pub struct TerraformResource<T> {
    class: v8::Global<v8::Function>,
    /// (See documentation on [`Class`]).
    _pd: PhantomData<T>,
}

rust_converter!(
    (TerraformResource<Class>, Resource),
    |&self, scope, value| {
        let r#type = v8_string(scope, &value.r#type).into();
        let name = v8_string(scope, &value.name).into();
        let args = [r#type, name];
        self.class
            .open(scope)
            .new_instance(scope, &args[..])
            .expect("class constructor should not throw")
            .into()
    }
);

impl FileContextTerraform<Instance> {
    pub const CLASS_NAME: &'static str = "FileContextTerraform";

    /// Creates a new [`v8::Global`] object by loading [`Self::CLASS_NAME`] from the `scope` and creating an instance.
    pub fn try_new(scope: &mut HandleScope) -> Result<Self, DDSAJsRuntimeError> {
        let js_class = load_function(scope, Self::CLASS_NAME)?;
        let js_class = js_class.open(scope);
        let args = [v8::undefined(scope).into()];
        let v8_object = js_class
            .new_instance(scope, &args[..])
            .expect("class constructor should not throw");
        let v8_object = v8::Global::new(scope, v8_object);
        let s_resource_map = v8_interned(scope, "resources");
        let s_resource_map = v8::Global::new(scope, s_resource_map);
        Ok(Self {
            v8_object,
            s_resource_map,
            _pd: PhantomData,
        })
    }

    /// Assigns either the provided [`v8::Global`] array to the JavaScript object's [`FileContextTerraform::s_resource_map`] key,
    /// or `undefined` if no array is provided.
    pub fn set_module_resource_array(
        &self,
        scope: &mut HandleScope,
        array: Option<&v8::Global<v8::Array>>,
    ) {
        if let Some(v8_map) = array {
            set_key_value(&self.v8_object, scope, &self.s_resource_map, |inner| {
                v8::Local::new(inner, v8_map).into()
            });
        } else {
            set_undefined(&self.v8_object, scope, &self.s_resource_map);
        }
    }

    /// Provides a reference to the [`v8::Global`] class instance object
    pub(crate) fn v8_object(&self) -> &v8::Global<v8::Object> {
        &self.v8_object
    }
}

impl TerraformResource<Class> {
    pub const CLASS_NAME: &'static str = "TerraformResource";

    /// Creates a new [`v8::Global`] function by loading [`Self::CLASS_NAME`] from the `scope`.
    pub fn try_new(
        scope: &mut v8::HandleScope,
    ) -> Result<Self, crate::analysis::ddsa_lib::common::DDSAJsRuntimeError> {
        let class = load_function(scope, Self::CLASS_NAME)?;
        Ok(Self {
            class,
            _pd: PhantomData,
        })
    }
}

#[cfg(test)]
mod tests {
    use deno_core::{v8, v8::HandleScope};

    use super::{FileContextTerraform, TerraformResource};
    use crate::analysis::ddsa_lib::common::{v8_interned, v8_uint, Instance};
    use crate::analysis::ddsa_lib::test_utils::{
        attach_as_global, cfg_test_runtime, js_class_eq, js_instance_eq, try_execute,
    };

    /// Creates a `FileContextTerraform`, prepopulated with the provided `resource_array` and exposed on `globalThis`
    /// with the provided `variable_name`.
    fn mount_context(
        scope: &mut HandleScope,
        variable_name: &str,
        resource_array: &[(&str, &str)],
    ) {
        let resources = v8::Array::new(scope, 0);
        for (index, (resource_type, resource_name)) in resource_array.iter().enumerate() {
            let resource = v8::Object::new(scope);

            let s_type = v8_interned(scope, "type");
            let resource_type = v8_interned(scope, resource_type);
            resource.set(scope, s_type.into(), resource_type.into());

            let s_name = v8_interned(scope, "name");
            let resource_name = v8_interned(scope, resource_name);
            resource.set(scope, s_name.into(), resource_name.into());

            let index = v8_uint(scope, index as u32);
            resources.set(scope, index.into(), resource.into());
        }
        let tf_resources = v8::Global::new(scope, resources);
        let tf_ctx = FileContextTerraform::<Instance>::try_new(scope).unwrap();
        tf_ctx.set_module_resource_array(scope, Some(&tf_resources));

        let tf_ctx_local = v8::Local::new(scope, tf_ctx.v8_object());
        attach_as_global(scope, tf_ctx_local, variable_name);
    }

    #[test]
    fn js_properties_canary() {
        // FileContextTerraform
        let instance_expected = &[
            // Variables
            "resources",
            // Methods
            "hasResource",
            "getResourcesOfType",
        ];
        assert!(js_instance_eq(
            FileContextTerraform::CLASS_NAME,
            instance_expected
        ));
        let class_expected = &[];
        assert!(js_class_eq(
            FileContextTerraform::CLASS_NAME,
            class_expected
        ));

        // TerraformResource
        let instance_expected = &[
            // Variables
            "type", "name",
            // Methods
        ];
        assert!(js_instance_eq(
            TerraformResource::CLASS_NAME,
            instance_expected
        ));
        let class_expected = &[];
        assert!(js_class_eq(TerraformResource::CLASS_NAME, class_expected));
    }

    /// We only pass in the `resources`, which has unique type <> name pairs, but potentially has
    /// several resources with the same types.
    /// Thus, we use `hasResource` to see if a specific resource given a type and name is present.
    /// It's also possible we want every resource of a given type, so we also use `getResourcesOfType` to test this.
    #[test]
    fn unique_resources() {
        let mut runtime = cfg_test_runtime();
        let scope = &mut runtime.handle_scope();
        let tf_resources = &[
            ("aws_instance", "app"),
            ("google_compute_instance", "cache"),
            ("google_storage_bucket", "db"),
            ("aws_instance", "cache"),
        ];
        mount_context(scope, "TERRAFORM", tf_resources);

        let code = "\
TERRAFORM.hasResource('google_storage_bucket', 'db');
";
        let return_val = try_execute(scope, code).unwrap().is_true();

        assert_eq!(return_val, true);

        let code = "\
TERRAFORM.getResourcesOfType('aws_instance').map(r => r.name).join(',');
";
        let return_val = try_execute(scope, code)
            .unwrap()
            .to_rust_string_lossy(scope);
        assert_eq!(return_val, "app,cache");
    }

    /// Here we test that we can fetch all the resources.
    #[test]
    fn get_all_resources() {
        let mut runtime = cfg_test_runtime();
        let scope = &mut runtime.handle_scope();
        let tf_resources = &[
            ("aws_instance", "app"),
            ("google_compute_instance", "cache"),
        ];
        mount_context(scope, "TERRAFORM", tf_resources);
        let code = "\
TERRAFORM.resources.map(r => `${r.type}:${r.name}`).join(',');
";
        let return_val = try_execute(scope, code)
            .unwrap()
            .to_rust_string_lossy(scope);
        assert_eq!(return_val, "aws_instance:app,google_compute_instance:cache");
    }
}
