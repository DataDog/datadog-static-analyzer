// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::analysis::ddsa_lib::common::v8_string;
use crate::analysis::ddsa_lib::v8_ds::MirroredIndexMap;
use crate::analysis::languages::go;
use deno_core::v8;
use deno_core::v8::HandleScope;

/// Structure for the file context that is specific to Go.
#[derive(Debug)]
pub struct FileContextGo {
    packages_aliased: MirroredIndexMap<String, String>,
}

impl FileContextGo {
    pub fn new(scope: &mut HandleScope) -> Self {
        Self {
            packages_aliased: MirroredIndexMap::new(scope),
        }
    }

    /// Queries the `tree_sitter::Tree` and updates the internal [`MirroredIndexMap`] with the query results.
    pub fn update_state(&mut self, scope: &mut HandleScope, tree: &tree_sitter::Tree, code: &str) {
        self.packages_aliased.clear(scope);

        for go::PackageImport {
            package_name,
            path: import_path,
        } in go::parse_imports_with_tree(code, tree)
        {
            self.packages_aliased.insert_with(
                scope,
                package_name.to_string(),
                import_path.to_string(),
                |scope, _, _| {
                    let v8_key = v8_string(scope, package_name);
                    let v8_value = v8_string(scope, import_path);
                    (v8_key.into(), v8_value.into())
                },
            );
        }
    }

    /// Clears the internal [`MirroredIndexMap`] of any package aliases.
    pub fn clear(&mut self, scope: &mut HandleScope) {
        self.packages_aliased.clear(scope);
    }

    /// Returns a reference to the [`v8::Global`] map backing the package to alias map.
    pub(crate) fn package_alias_v8_map(&self) -> &v8::Global<v8::Map> {
        self.packages_aliased.v8_map()
    }

    /// Returns a reference to the `MirroredIndexMap` containing the package to alias map.
    #[cfg(test)]
    pub fn package_alias_map(&self) -> &MirroredIndexMap<String, String> {
        &self.packages_aliased
    }
}

#[cfg(test)]
mod tests {
    use crate::analysis::ddsa_lib::context::file_go::FileContextGo;
    use crate::analysis::ddsa_lib::test_utils::cfg_test_v8;
    use crate::analysis::tree_sitter::get_tree;
    use crate::model::common::Language;

    /// Tests that imports are properly exposed via the context.
    #[test]
    fn context_get_imports() {
        let mut runtime = cfg_test_v8().deno_core_rt();
        let scope = &mut runtime.handle_scope();
        let mut ctx_go = FileContextGo::new(scope);

        let mut assert_test = |code: &str, expected: &[(&str, &str)]| {
            let tree = get_tree(code, &Language::Go).unwrap();
            ctx_go.update_state(scope, &tree, code);
            assert_eq!(ctx_go.packages_aliased.len(), expected.len());
            for (j, (expected_name, expected_path)) in expected.iter().enumerate() {
                let (map_alias, map_package) = ctx_go.packages_aliased.get_index(j).unwrap();
                assert_eq!(map_alias, expected_name);
                assert_eq!(map_package, expected_path);
            }
        };

        let code_1 = r#"
import (
    "fmt"
    by "bytes"
)
"#;
        let expected_1 = vec![("fmt", "fmt"), ("by", "bytes")];
        assert_test(code_1, &expected_1);

        // Additionally, test that multiple calls to `update_state` properly clear state.
        let code_2 = r#"
import "strconv"
"#;
        let expected_2 = vec![("strconv", "strconv")];
        assert_test(code_2, &expected_2);
    }
}
