// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::analysis::ddsa_lib::common::v8_string;
use crate::analysis::ddsa_lib::v8_ds::MirroredIndexMap;
use crate::analysis::tree_sitter::get_tree_sitter_language;
use crate::model::common::Language;
use deno_core::v8;
use deno_core::v8::HandleScope;
use streaming_iterator::StreamingIterator;

/// Structure for the file context that is specific to Go.
#[derive(Debug)]
pub struct FileContextGo {
    ts_query: tree_sitter::Query,
    packages_aliased: MirroredIndexMap<String, String>,
}

impl FileContextGo {
    pub fn new(scope: &mut HandleScope) -> Self {
        let packages_aliased = MirroredIndexMap::new(scope);

        let query_string = r#"
(import_spec
    name: (_)? @name
    path: (_) @package
)
    "#;

        let ts_query =
            tree_sitter::Query::new(&get_tree_sitter_language(&Language::Go), query_string)
                .expect("query has valid syntax");

        Self {
            ts_query,
            packages_aliased,
        }
    }

    /// Queries the `tree_sitter::Tree` and updates the internal [`MirroredIndexMap`] with the query results.
    pub fn update_state(&mut self, scope: &mut HandleScope, tree: &tree_sitter::Tree, code: &str) {
        self.packages_aliased.clear(scope);
        // Query to get all the packages and their potential aliases. The first capture is the potential alias,
        // the second capture is the name of the package.

        let mut query_cursor = tree_sitter::QueryCursor::new();
        let mut query_result =
            query_cursor.matches(&self.ts_query, tree.root_node(), code.as_bytes());
        while let Some(query_match) = query_result.next() {
            let mut package_name: Option<&str> = None;
            let mut package_alias: Option<&str> = None;

            for capture in query_match.captures {
                let start = capture.node.byte_range().start;
                let end = capture.node.byte_range().end;

                if capture.index == 0 {
                    package_alias = Some(code.get(start..end).unwrap());
                }

                // The package name includes the quotes. We do not want to capture the quotes, we only want
                // to capture the package name. For this reason, we need to play with -1/+1 with the index.
                if capture.index == 1 {
                    package_name = Some(code.get(start + 1..end - 1).unwrap());
                }
            }

            // if we have the alias, add it. If we have only the package name, add the package name as an alias
            // so that we have a simple mapping between package and full qualified name

            let normalized = match (package_alias, package_name) {
                (Some(alias), Some(pkg)) => Some((alias, pkg)),
                (None, Some(pkg)) => Some(
                    pkg.rsplit_once('/')
                        .map(|(_, alias)| (alias, pkg))
                        // If the path is a single word, treat that as the alias
                        .unwrap_or((pkg, pkg)),
                ),
                _ => None,
            };

            if let Some((key, value)) = normalized {
                self.packages_aliased.insert_with(
                    scope,
                    key.to_string(),
                    value.to_string(),
                    |scope, _, _| {
                        let v8_key = v8_string(scope, key);
                        let v8_value = v8_string(scope, value);
                        (v8_key.into(), v8_value.into())
                    },
                );
            }
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
    use crate::analysis::ddsa_lib::test_utils::cfg_test_runtime;
    use crate::analysis::tree_sitter::get_tree;
    use crate::model::common::Language;

    #[test]
    fn test_get_file_context_go() {
        let mut runtime = cfg_test_runtime();
        let scope = &mut runtime.handle_scope();
        let mut ctx_go = FileContextGo::new(scope);

        let code1 = r#"
import (
    "math/rand"
    "fmt"
    crand1 "crypto/rand"
    crand2 "crypto/rand"
    foo "fmt"
)
"#;
        let expected1 = vec![
            ["rand", "math/rand"],
            ["fmt", "fmt"],
            ["crand1", "crypto/rand"],
            ["crand2", "crypto/rand"],
            ["foo", "fmt"],
        ];
        // Additionally test that multiple calls to `update_state` properly clear state.
        let code2 = r#"
import (
    "fmt"
    by "bytes"
)
"#;
        let expected2 = vec![["fmt", "fmt"], ["by", "bytes"]];
        let code3 = r#"
import "strconv"
"#;
        let expected3 = vec![["strconv", "strconv"]];

        let tests = [(code1, expected1), (code2, expected2), (code3, expected3)];

        for (idx, (code, test_expected)) in tests.iter().enumerate() {
            // The number of detections from the array element before
            let required_prev = if let Some(prev_idx) = idx.checked_sub(1) {
                tests.get(prev_idx).map(|(_, v)| v.len()).unwrap()
            } else {
                0
            };
            assert_eq!(ctx_go.packages_aliased.len(), required_prev);

            let tree = get_tree(code, &Language::Go).unwrap();
            ctx_go.update_state(scope, &tree, code);
            assert_eq!(ctx_go.packages_aliased.len(), test_expected.len());

            for (j, [expected_alias, expected_package]) in test_expected.iter().enumerate() {
                let (map_alias, map_package) = ctx_go.packages_aliased.get_index(j).unwrap();
                assert_eq!(map_alias, expected_alias);
                assert_eq!(map_package, expected_package);
            }
        }
    }
}
