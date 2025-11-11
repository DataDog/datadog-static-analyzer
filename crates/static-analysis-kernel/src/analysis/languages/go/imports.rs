// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::analysis::languages::ts_node_text;
use crate::analysis::tree_sitter::{get_tree, get_tree_sitter_language};
use crate::model::common::Language;
use std::sync::LazyLock;
use streaming_iterator::StreamingIterator;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct PackageImport<'a> {
    /// See Go language specification for [`PackageName`].
    ///
    /// [`PackageName`]: https://go.dev/ref/spec#Import_declarations
    pub package_name: &'a str,
    /// See Go language specification for [`ImportPath`].
    ///
    /// [`ImportPath`]: https://go.dev/ref/spec#Import_declarations
    pub path: &'a str,
}

/// Returns the imports in the provided Go source code as a list, which is ordered by line ascending.
/// If an import is specified without a name, the last path-delimited identifier will be used.
///
/// ```text
/// import   "lib/math"    // PackageName == "math", ImportPath == "lib/math"
/// import m "lib/math"    // PackageName == "m",    ImportPath == "lib/math"
/// import   "fmt"         // PackageName == "fm",   ImportPath == "fmt"
/// ```
///
/// This function parses the source code from scratch.
/// If you already have a parsed tree, you should use [`parse_imports_with_tree`].
pub fn parse_imports(source_code: &str) -> Vec<PackageImport<'_>> {
    get_tree(source_code, &Language::Go)
        .map(|tree| parse_imports_with_tree(source_code, &tree))
        .unwrap_or_default()
}

/// Returns imports for the provided parse tree. See [`parse_imports`] for documentation.
pub fn parse_imports_with_tree<'text>(
    source_code: &'text str,
    tree: &tree_sitter::Tree,
) -> Vec<PackageImport<'text>> {
    static TS_QUERY: LazyLock<tree_sitter::Query> = LazyLock::new(|| {
        let query_string = r#"
(import_spec
    name: (_)? @name
    path: (_) @package
)
    "#;

        tree_sitter::Query::new(&get_tree_sitter_language(&Language::Go), query_string)
            .expect("query should have valid syntax")
    });

    let mut imports = Vec::<PackageImport>::new();
    // Query to get all the packages and their potential aliases. The first capture is potentially
    // an alias, and the second capture is always the name of the package.
    let mut query_cursor = tree_sitter::QueryCursor::new();
    let mut query_result =
        query_cursor.matches(&TS_QUERY, tree.root_node(), source_code.as_bytes());
    while let Some(query_match) = query_result.next() {
        let mut package_name: Option<&str> = None;
        let mut package_alias: Option<&str> = None;

        for capture in query_match.captures {
            if capture.index == 0 {
                package_alias = Some(ts_node_text(source_code, capture.node));
            }

            // The package name includes the quotes. We do not want to capture the quotes, we only want
            // to capture the package name. For this reason, we need to play with -1/+1 with the index.
            if capture.index == 1 {
                let name_with_quotes = ts_node_text(source_code, capture.node);
                // tree-sitter-go grammar invariant: the node text includes the quotation marks,
                // so this indexing can never trigger a panic.
                let name_sans_quotes = &name_with_quotes[1..name_with_quotes.len() - 1];
                package_name = Some(name_sans_quotes);
            }
        }

        // if we have the alias, add it. If we have only the package name, add the package name as an alias
        // so that we have a simple mapping between package and full qualified name
        match (package_alias, package_name) {
            (Some(alias), Some(pkg)) => imports.push(PackageImport {
                package_name: alias,
                path: pkg,
            }),
            (None, Some(pkg)) => imports.push(
                pkg.rsplit_once('/')
                    .map(|(_, alias)| PackageImport {
                        package_name: alias,
                        path: pkg,
                    })
                    // If the path is a single word, treat that as the alias
                    .unwrap_or_else(|| PackageImport {
                        package_name: pkg,
                        path: pkg,
                    }),
            ),
            _ => {}
        };
    }
    imports
}

#[cfg(test)]
mod tests {
    use super::{parse_imports, PackageImport};

    #[test]
    fn parse_imports_multi() {
        let code = r#"
import (
    "math/rand"
    "fmt"
    crand1 "crypto/rand"
    crand2 "crypto/rand"
    foo "fmt"
)
"#;
        let expected = vec![
            ("rand", "math/rand"),
            ("fmt", "fmt"),
            ("crand1", "crypto/rand"),
            ("crand2", "crypto/rand"),
            ("foo", "fmt"),
        ]
        .into_iter()
        .map(|(package_name, path)| PackageImport { package_name, path })
        .collect::<Vec<_>>();

        assert_eq!(parse_imports(code), expected);
    }
}
