// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use deno_core::v8;
use deno_core::v8::HandleScope;
use std::borrow::Cow;

use crate::analysis::ddsa_lib::common::{Class, DDSAJsRuntimeError};
use crate::analysis::ddsa_lib::js::JSPackageImport;
use crate::analysis::ddsa_lib::v8_ds::MirroredVec;
use crate::analysis::languages;

/// Structure for the file context that is specific to JavaScript.
#[derive(Debug)]
pub struct FileContextJavaScript {
    imports: MirroredVec<PackageImport, JSPackageImport<Class>>,
}

/// A duplicate of [`languages::javascript::PackageImport`](crate::analysis::languages::javascript::PackageImport),
/// except that this struct is guaranteed to own its data.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PackageImport {
    pub name: String,
    pub imported_from: Option<String>,
}

impl FileContextJavaScript {
    pub fn new(scope: &mut HandleScope) -> Result<Self, DDSAJsRuntimeError> {
        let imports = MirroredVec::new(JSPackageImport::try_new(scope)?, scope);
        Ok(Self { imports })
    }

    pub fn update_state(&mut self, scope: &mut HandleScope, tree: &tree_sitter::Tree, code: &str) {
        let imports = languages::javascript::parse_imports_with_tree(code, tree);
        let owned_imports = imports
            .into_iter()
            .map(|pkg| PackageImport {
                name: pkg.name.into_owned(),
                imported_from: pkg.imported_from.map(Cow::into_owned),
            })
            .collect::<Vec<_>>();

        self.imports.set_data(scope, owned_imports);
    }

    pub fn clear(&mut self, scope: &mut HandleScope) {
        self.imports.clear(scope);
    }

    /// Returns a reference to the [`v8::Global`] array backing the imports.
    pub(crate) fn imports_v8_array(&self) -> &v8::Global<v8::Array> {
        self.imports.v8_array()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::ddsa_lib::test_utils::cfg_test_v8;
    use crate::analysis::tree_sitter::get_tree;
    use crate::model::common::Language;

    /// Tests that imports are properly exposed via the context.
    #[test]
    fn test_get_js_imports() {
        let mut runtime = cfg_test_v8().deno_core_rt();
        let scope = &mut runtime.handle_scope();
        let mut ctx_js = FileContextJavaScript::new(scope).unwrap();

        let code_1 = "\
import { foo } from './module1/file1.js';
import { bar } from './module1/file2.js';
";
        let expected_1 = vec![("foo", "file1"), ("bar", "file2")]
            .into_iter()
            .map(|(name, imported_from)| PackageImport {
                name: name.to_string(),
                imported_from: Some(imported_from.to_string()),
            })
            .collect::<Vec<_>>();
        let tree_1 = get_tree(code_1, &Language::JavaScript).unwrap();
        ctx_js.update_state(scope, &tree_1, code_1);
        assert_eq!(ctx_js.imports.get(0).unwrap(), &expected_1[0]);
        assert_eq!(ctx_js.imports.get(1).unwrap(), &expected_1[1]);

        // Additionally, test that multiple calls to `update_state` properly clear state.
        let code_2 = "\
import { baz } from './module1/file3.js';
";
        let expected_2 = vec![PackageImport {
            name: "baz".to_string(),
            imported_from: Some("file3".to_string()),
        }];
        let tree_2 = get_tree(code_2, &Language::JavaScript).unwrap();
        ctx_js.update_state(scope, &tree_2, code_2);
        assert_eq!(ctx_js.imports.get(0).unwrap(), &expected_2[0]);
    }
}
