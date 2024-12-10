// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::analysis::languages::ts_node_text;
use crate::analysis::tree_sitter::{get_tree, get_tree_sitter_language};
use crate::model::common::Language;
use std::borrow::Cow;
use std::sync::LazyLock;
use streaming_iterator::StreamingIterator;

/// JavaScript module representation, which consists of a name and where it's imported from
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PackageImport<'a> {
    pub name: Cow<'a, str>,
    pub imported_from: Option<Cow<'a, str>>,
}

impl<'a> PackageImport<'a> {
    /// Returns `true` if the import was for a module, or `false` if it was an export within a module.
    pub fn is_module(&self) -> bool {
        self.imported_from.is_none()
    }
}

pub const JS_IMPORTS_QUERY: &str = r#"
; import '<name>'
(import_statement
  "import"
  .
  source: (string (string_fragment) @name))

; import { <name> } from '<imported_from>'
; import { _ as <name> } from '<imported_from>'
(import_statement
  (import_clause
    (named_imports
      (import_specifier
        .
        [
          name: (identifier) @name
          name: (
            (_) @name_except_default
            "as"
          )
        ]
        .
      )
    )
  )
  "from"
  source: (string (string_fragment) @imported_from)
)

; import <name> from '<imported_from>'
(import_statement
  (import_clause
    .
    (identifier) @name
  )
  "from"
  source: (string (string_fragment) @imported_from))

; import * as _ from "<name>"
(import_statement
  (import_clause
    (namespace_import
        "*"
        "as"
    )
  )
  "from"
  source: (string (string_fragment) @name))

; const _ = require('<name>')
(lexical_declaration
  kind: "const"
  (variable_declarator
    name: (identifier)
    "="
    value: (call_expression
      function: (identifier) @_require
      (#eq? @_require "require")
      arguments: (arguments . (string (string_fragment) @name) .)
    )
  )
)

; const { <name> } = require('<imported_from>')
(lexical_declaration
  kind: "const"
  (variable_declarator
    name: (object_pattern
            (shorthand_property_identifier_pattern) @name)
    "="
    value: (call_expression
      function: (identifier) @_require
      (#eq? @_require "require")
      arguments: (arguments . (string (string_fragment) @imported_from) .)
    )
  )
)

; const <name> = await import('<imported_from>')
(lexical_declaration
  kind: "const"
  (variable_declarator
    name: (identifier) @name
    "="
    value: (await_expression
      (call_expression
        function: (import)
        arguments: (arguments . (string (string_fragment) @imported_from) .)
      )
    )
  )
)

; const { <name> } = await import('<imported_from>')
(lexical_declaration
  kind: "const"
  (variable_declarator
    name: (object_pattern
            (shorthand_property_identifier_pattern) @name)
    "="
    value: (await_expression
      (call_expression
        function: (import)
        arguments: (arguments . (string (string_fragment) @imported_from) .)
      )
    )
  )
)
"#;

/// Returns the imports in the provided JavaScript source code.
///
/// This function parses the source code from scratch.
/// If you already have a parsed tree, you should use [`parse_imports_with_tree`].
pub fn parse_imports(source_code: &str) -> Vec<PackageImport> {
    get_tree(source_code, &Language::JavaScript)
        .map(|tree| parse_imports_with_tree(source_code, &tree))
        .unwrap_or_default()
}

/// Returns imports for the provided parse tree. See [`parse_imports`] for documentation.
pub fn parse_imports_with_tree<'text>(
    source_code: &'text str,
    tree: &tree_sitter::Tree,
) -> Vec<PackageImport<'text>> {
    static TS_QUERY: LazyLock<tree_sitter::Query> = LazyLock::new(|| {
        let ts_lang = &get_tree_sitter_language(&Language::JavaScript);
        tree_sitter::Query::new(ts_lang, JS_IMPORTS_QUERY).expect("query should have valid syntax")
    });

    let mut query_cursor = tree_sitter::QueryCursor::new();
    let query_result = query_cursor.matches(&TS_QUERY, tree.root_node(), source_code.as_bytes());

    query_result
        .filter_map_deref(|query_match| {
            let mut name = None;
            let mut imported_from = None;
            let mut has_default = false;

            for capture in query_match.captures {
                let capture_name = TS_QUERY.capture_names()[capture.index as usize];
                let path_text = ts_node_text(source_code, capture.node);
                match capture_name {
                    "name" => {
                        if let Some(path) = normalize_path(path_text) {
                            name = Some(path)
                        } else {
                            // If this path has a special name, filter it out
                            return None;
                        };
                    }
                    "name_except_default" => {
                        let name_text = path_text;
                        if name_text == "default" {
                            has_default = true;
                        }
                        name = Some(Cow::Borrowed(name_text));
                    }
                    "imported_from" => {
                        if let Some(path) = normalize_path(path_text) {
                            imported_from = Some(path)
                        } else {
                            // If this path has a special name, filter it out
                            return None;
                        }
                    }
                    "_require" => {}
                    _ => unreachable!(),
                }
            }

            if has_default {
                // Consider import { default as foo } from './foo/bar.js'.
                // Ordinarily, `bar` would be `imported_from`, but since it's a default,
                // we consider `bar` to be the name being imported, and it is aliased as foo.
                name = imported_from.take();
            }

            Some(PackageImport {
                name: name.expect("name should always be set"),
                imported_from,
            })
        })
        .collect::<Vec<_>>()
}

/// Transforms a JavaScript import into the module name
/// This will take the file stem path and remove the file extension if any
///
/// e.g. './foo/bar.js' -> 'bar'
///
/// This may return None if the path is a special edge case, for example `../..` will
/// return None because it has no file stem.
fn normalize_path(s: &str) -> Option<Cow<'_, str>> {
    std::path::Path::new(s)
        .file_stem()
        .map(|s| s.to_string_lossy())
}

#[cfg(test)]
mod tests {
    use super::{parse_imports, PackageImport};
    use std::borrow::Cow;

    #[test]
    fn parse_inputs_multi() {
        struct TestCase {
            code: &'static str,
            expected: Vec<(&'static str, Option<&'static str>)>,
        }

        let tests = [
            // import
            TestCase {
                code: r#"
import './foo/bar.js';
"#,
                expected: vec![("bar", None)],
            },
            TestCase {
                code: r#"
import { foo } from './module1/file1.js';
import { bar as baz } from './module2/file2.js';
"#,
                expected: vec![("foo", Some("file1")), ("bar", Some("file2"))],
            },
            TestCase {
                code: r#"
import foo from './module1/file1.js';
import bar from './module2/file2.js';
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
import foo, { bar, baz } from './module1/file1.js';
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
const { foo } = require('./module1/file1.js');
const { bar } = require('./module2/file2.js');
const { baz, qux } = require('./module3/file3.js');
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
const foo = await import('./module1/file1.js');
"#,
                expected: vec![("foo", Some("file1"))],
            },
            TestCase {
                code: r#"
const { bar } = await import('./module2/file2.js');
"#,
                expected: vec![("bar", Some("file2"))],
            },
            TestCase {
                code: r#"
import { default as foo } from './foo/bar.js';
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
            let actual = parse_imports(test.code);
            let expected = test
                .expected
                .into_iter()
                .map(|(name, imported_from)| PackageImport {
                    name: Cow::Borrowed(name),
                    imported_from: imported_from.map(Cow::Borrowed),
                })
                .collect::<Vec<_>>();

            assert_eq!(actual, expected);
        }
    }
}
