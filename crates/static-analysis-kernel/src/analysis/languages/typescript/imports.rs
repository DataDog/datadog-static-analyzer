// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::analysis::languages::javascript;
use crate::analysis::tree_sitter::{get_tree, get_tree_sitter_language};
use crate::model::common::Language;
use std::sync::LazyLock;

/// Because the tree-sitter-typescript grammar essentially "inherits" the
/// tree-sitter-javascript grammar, we can use the existing query.
const TS_IMPORTS_QUERY: &str = javascript::JS_IMPORTS_QUERY;

/// Returns the imports in the provided TypeScript source code.
///
/// This function parses the source code from scratch.
/// If you already have a parsed tree, you should use [`parse_imports_with_tree`].
pub fn parse_imports(source_code: &str) -> Vec<javascript::PackageImport> {
    get_tree(source_code, &Language::TypeScript)
        .map(|tree| parse_imports_with_tree(source_code, &tree))
        .unwrap_or_default()
}

/// Returns imports for the provided parse tree. See [`parse_imports`] for documentation.
pub fn parse_imports_with_tree<'text>(
    source_code: &'text str,
    tree: &tree_sitter::Tree,
) -> Vec<javascript::PackageImport<'text>> {
    static TS_QUERY: LazyLock<tree_sitter::Query> = LazyLock::new(|| {
        let ts_lang = &get_tree_sitter_language(&Language::TypeScript);
        tree_sitter::Query::new(ts_lang, TS_IMPORTS_QUERY).expect("query should have valid syntax")
    });

    javascript::parse_imports_with_tree_inner(source_code, tree, &TS_QUERY)
}

#[cfg(test)]
mod tests {
    use crate::analysis::languages::javascript;
    use std::borrow::Cow;

    /// NOTE: All the [`TestCase`] structs in this are transliterated from the JavaScript imports test.
    #[test]
    fn test_parse_imports() {
        struct TestCase {
            code: &'static str,
            expected: Vec<(&'static str, Option<&'static str>)>,
        }

        let tests = [
            // import
            TestCase {
                code: r#"
import './foo/bar.ts';
"#,
                expected: vec![("bar", None)],
            },
            TestCase {
                code: r#"
import { foo } from './module1/file1.ts';
import { bar as baz } from './module2/file2.ts';
"#,
                expected: vec![("foo", Some("file1")), ("bar", Some("file2"))],
            },
            TestCase {
                code: r#"
import foo from './module1/file1.ts';
import bar from './module2/file2.ts';
"#,
                expected: vec![("foo", Some("file1")), ("bar", Some("file2"))],
            },
            TestCase {
                code: r#"
import * as fs2 from "fs";
"#,
                expected: vec![("fs", None)],
            },
            TestCase {
                code: r#"
import foo, { bar, baz } from './module1/file1.ts';
"#,
                expected: vec![
                    ("bar", Some("file1")),
                    ("baz", Some("file1")),
                    ("foo", Some("file1")),
                ],
            },
            // require
            TestCase {
                code: r#"
const fs = require('fs');
"#,
                expected: vec![("fs", None)],
            },
            TestCase {
                code: r#"
const { foo } = require('./module1/file1.ts');
const { bar } = require('./module2/file2.ts');
const { baz, qux } = require('./module3/file3.ts');
"#,
                expected: vec![
                    ("foo", Some("file1")),
                    ("bar", Some("file2")),
                    ("baz", Some("file3")),
                    ("qux", Some("file3")),
                ],
            },
            // dynamic import
            TestCase {
                code: r#"
const foo = await import('./module1/file1.ts');
"#,
                expected: vec![("foo", Some("file1"))],
            },
            TestCase {
                code: r#"
const { bar } = await import('./module2/file2.ts');
"#,
                expected: vec![("bar", Some("file2"))],
            },
            TestCase {
                code: r#"
import { default as foo } from './foo/bar.ts';
"#,
                expected: vec![("bar", None)],
            },
            // edge cases
            TestCase {
                code: r#"
import '../..';
"#,
                expected: vec![],
            },
        ];

        for test in tests {
            let actual = javascript::parse_imports(test.code);
            let expected = test
                .expected
                .into_iter()
                .map(|(name, imported_from)| javascript::PackageImport {
                    name: Cow::Borrowed(name),
                    imported_from: imported_from.map(Cow::Borrowed),
                })
                .collect::<Vec<_>>();

            assert_eq!(actual, expected);
        }
    }
}
