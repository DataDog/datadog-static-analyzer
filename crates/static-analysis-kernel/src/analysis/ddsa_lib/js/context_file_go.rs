// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::analysis::ddsa_lib::common::{
    load_function, set_key_value, set_undefined, v8_interned, DDSAJsRuntimeError, Instance,
};
use deno_core::v8;
use deno_core::v8::HandleScope;
use std::marker::PhantomData;

/// A [`v8::Global`] object created from the ES6 class `FileContextGo`.
#[derive(Debug)]
pub struct FileContextGo<T> {
    v8_object: v8::Global<v8::Object>,
    // Cached keys
    s_alias_map: v8::Global<v8::String>,
    s_is_cached: v8::Global<v8::String>,
    _pd: PhantomData<T>,
}

impl FileContextGo<Instance> {
    pub const CLASS_NAME: &'static str = "FileContextGo";

    /// Creates a new [`v8::Global`] object by loading [`Self::CLASS_NAME`] from the `scope` and creating an instance.
    pub fn try_new(scope: &mut HandleScope) -> Result<Self, DDSAJsRuntimeError> {
        let js_class = load_function(scope, Self::CLASS_NAME)?;
        let js_class = js_class.open(scope);
        let args = [v8::undefined(scope).into()];
        let v8_object = js_class
            .new_instance(scope, &args[..])
            .expect("class constructor should not throw");
        let v8_object = v8::Global::new(scope, v8_object);
        let s_alias_map = v8_interned(scope, "aliasMap");
        let s_alias_map = v8::Global::new(scope, s_alias_map);
        let s_is_cached = v8_interned(scope, "__js_isCached");
        let s_is_cached = v8::Global::new(scope, s_is_cached);
        Ok(Self {
            v8_object,
            s_alias_map,
            s_is_cached,
            _pd: PhantomData,
        })
    }

    /// Assigns either the provided `v8::Global` map to the JavaScript object's [`FileContextGo::s_alias_map`] key,
    /// or `undefined` if no map is provided.
    pub fn set_pkg_alias_map(&self, scope: &mut HandleScope, map: Option<&v8::Global<v8::Map>>) {
        if let Some(v8_map) = map {
            set_key_value(&self.v8_object, scope, &self.s_alias_map, |inner| {
                v8::Local::new(inner, v8_map).into()
            });
        } else {
            set_undefined(&self.v8_object, scope, &self.s_alias_map);
        }
    }

    /// Provides a reference to the [`v8::Global`] class instance object
    pub(crate) fn v8_object(&self) -> &v8::Global<v8::Object> {
        &self.v8_object
    }
}

#[cfg(test)]
mod tests {
    use crate::analysis::ddsa_lib::common::{attach_as_global, v8_interned, v8_string, Instance};
    use crate::analysis::ddsa_lib::js::context_file_go::FileContextGo;
    use crate::analysis::ddsa_lib::test_utils::{
        cfg_test_runtime, js_class_eq, js_instance_eq, try_execute,
    };
    use deno_core::v8;
    use deno_core::v8::HandleScope;

    /// Creates a `FileContextGo`, prepopulated with the provided `mapping` and exposed on `globalThis`
    /// with the provided `variable_name`.
    fn mount_context(scope: &mut HandleScope, variable_name: &str, mapping: &[(&str, &str)]) {
        let package_map = v8::Map::new(scope);
        for (alias, name) in mapping {
            let key = v8_interned(scope, alias);
            let value = v8_interned(scope, name);
            package_map.set(scope, key.into(), value.into());
        }
        let package_map = v8::Global::new(scope, package_map);
        let go_ctx = FileContextGo::<Instance>::try_new(scope).unwrap();
        go_ctx.set_pkg_alias_map(scope, Some(&package_map));

        let go_ctx_local = v8::Local::new(scope, go_ctx.v8_object());
        attach_as_global(scope, go_ctx_local, variable_name);
    }

    #[test]
    fn js_properties_canary() {
        let expected = &[
            // Variables
            "aliasMap",
            // Methods
            "getResolvedPackage",
            "packages",
        ];
        assert!(js_instance_eq(FileContextGo::CLASS_NAME, expected));
        let class_expected = &[];
        assert!(js_class_eq(FileContextGo::CLASS_NAME, class_expected));
    }

    /// We only pass in the `aliasMap`, which has unique aliases, but potentially duplicate fully-qualified names.
    /// Thus, we use `packages` as a getter, and this test ensures the getter properly returns de-duplicated names.
    #[test]
    fn unique_packages_array() {
        let mut runtime = cfg_test_runtime();
        let scope = &mut runtime.handle_scope();
        let mapping = &[
            ("alias_1", "alpha/pkg"),
            ("alias_2", "delta/pkg"),
            ("alias_3", "alpha/pkg"),
            ("alias_4", "bravo/pkg"),
        ];
        mount_context(scope, "GO", mapping);
        let code = "\
GO.packages.join(',');
";
        let return_val = try_execute(scope, code)
            .unwrap()
            .to_rust_string_lossy(scope);
        assert_eq!(return_val, "alpha/pkg,delta/pkg,bravo/pkg");
    }

    /// We only pass in the `aliasMap`, which has unique aliases, but potentially duplicate fully-qualified names.
    /// Thus, we use `packages` as a getter, and this test ensures the getter properly returns de-duplicated names.
    #[test]
    fn package_name_lookup() {
        let mut runtime = cfg_test_runtime();
        let scope = &mut runtime.handle_scope();
        let mapping = &[
            ("alias_1", "alpha/pkg"),
            ("alias_2", "delta/pkg"),
            ("alias_3", "alpha/pkg"),
            ("alias_4", "bravo/pkg"),
        ];
        mount_context(scope, "GO", mapping);
        let code = r#"
const names = ["alias_1", "alias_2", "alias_3", "alias_4"].map((alias) => {
    return GO.getResolvedPackage(alias);
});
names.join(",");
"#;
        let return_val = try_execute(scope, code)
            .unwrap()
            .to_rust_string_lossy(scope);
        assert_eq!(return_val, "alpha/pkg,delta/pkg,alpha/pkg,bravo/pkg");
    }
}
