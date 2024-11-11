// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use deno_core::v8;
use deno_core::v8::HandleScope;
use streaming_iterator::StreamingIterator;

use crate::analysis::ddsa_lib::common::{Class, DDSAJsRuntimeError};
use crate::analysis::ddsa_lib::js::JSPackageImport;
use crate::analysis::ddsa_lib::v8_ds::MirroredVec;
use crate::analysis::tree_sitter::get_tree_sitter_language;
use crate::model::common::Language;

/// Terraform-specific file context
#[derive(Debug)]
pub struct FileContextJavaScript {
    query: tree_sitter::Query,
    imports: MirroredVec<PackageImport, JSPackageImport<Class>>,
}

/// JavaScript module representation, which consists of a name and where it's imported from
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct PackageImport {
    pub name: String,
    pub imported_from: Option<String>,
}

const JS_IMPORTS_QUERY: &str = r#"
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

impl FileContextJavaScript {
    pub fn new(scope: &mut HandleScope) -> Result<Self, DDSAJsRuntimeError> {
        let query = tree_sitter::Query::new(
            &get_tree_sitter_language(&Language::JavaScript),
            JS_IMPORTS_QUERY,
        )
        .expect("query has valid syntax");
        let imports = MirroredVec::new(JSPackageImport::try_new(scope)?, scope);

        Ok(Self { query, imports })
    }

    pub fn update_state(&mut self, scope: &mut HandleScope, tree: &tree_sitter::Tree, code: &str) {
        let mut query_cursor = tree_sitter::QueryCursor::new();

        // Transforms a JavaScript import into the module name
        // This will take the file stem path and remove the file extension if any
        //
        // e.g. './foo/bar.js' -> 'bar'
        //
        // This may return None if the path is a special edge case, for example `../..` will
        // return None because it has no file stem.
        let normalize_path = |s: &str| -> Option<String> {
            std::path::Path::new(s)
                .file_stem()
                .map(|s| s.to_string_lossy().to_string())
        };

        let query_result = query_cursor.matches(&self.query, tree.root_node(), code.as_bytes());
        let imports = query_result
            .filter_map_deref(|query_match| {
                let mut name = None;
                let mut imported_from = None;
                let mut has_default = false;

                for capture in query_match.captures {
                    let start = capture.node.byte_range().start;
                    let end = capture.node.byte_range().end;
                    let capture_name = self.query.capture_names()[capture.index as usize];
                    match capture_name {
                        "name" => {
                            name = if let Some(path) = normalize_path(code.get(start..end).unwrap())
                            {
                                Some(path)
                            } else {
                                // If this path has a special name, filter it out
                                return None;
                            };
                        }
                        "name_except_default" => {
                            let name_text = code.get(start..end).unwrap();
                            if name_text == "default" {
                                has_default = true;
                            }
                            name = Some(name_text.to_string());
                        }
                        "imported_from" => {
                            imported_from =
                                if let Some(path) = normalize_path(code.get(start..end).unwrap()) {
                                    Some(path)
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
            .collect::<Vec<_>>();

        self.imports.set_data(scope, imports);
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
    use crate::analysis::ddsa_lib::test_utils::cfg_test_runtime;
    use crate::analysis::tree_sitter::get_tree;

    #[test]
    fn test_get_js_imports() {
        let mut runtime = cfg_test_runtime();
        let scope = &mut runtime.handle_scope();
        let mut ctx_js = FileContextJavaScript::new(scope).unwrap();

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
            let tree = get_tree(test.code, &Language::JavaScript).unwrap();
            ctx_js.update_state(scope, &tree, test.code);
            assert_eq!(ctx_js.imports.len(), test.expected.len());

            for (idx, (expected_name, expected_imported_from)) in test.expected.iter().enumerate() {
                let actual = ctx_js.imports.get(idx).unwrap();
                let expected_package_import = PackageImport {
                    name: expected_name.to_string(),
                    imported_from: expected_imported_from.map(|s| s.to_string()),
                };
                assert_eq!(actual, &expected_package_import);
            }
        }
    }
}
