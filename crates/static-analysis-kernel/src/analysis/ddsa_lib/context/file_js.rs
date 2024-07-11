// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use std::rc::Rc;
use std::sync::Arc;

use deno_core::v8::HandleScope;

use crate::analysis::ddsa_lib::common::{Class, DDSAJsRuntimeError};
use crate::analysis::ddsa_lib::js::JSPackageImport;
use crate::analysis::ddsa_lib::v8_ds::MirroredVec;
use crate::analysis::tree_sitter::get_tree_sitter_language;
use crate::model::common::Language;

/// Terraform-specific file context
#[derive(Debug)]
pub struct FileContextJavaScript {
    query: tree_sitter::Query,
    tree: Option<tree_sitter::Tree>,
    code: Option<Arc<str>>,
    cached_nodes: Option<Rc<MirroredVec<PackageImport, JSPackageImport<Class>>>>,
}

/// JavaScript module representation, which consists of a name, where it's imported from, and what
/// it's imported as
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct PackageImport {
    pub name: String,
    pub imported_from: Option<String>,
    pub imported_as: Option<String>,
}

const JS_IMPORTS_QUERY: &str = r#"
; import '<name>'
(import_statement
  "import"
  .
  source: (string (string_fragment) @name))

; import { <name> } from '<imported_from>'
; import { <imported_as> as <name> } from '<imported_from>'
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
            alias: (identifier) @imported_as
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

; import * as <imported_as> from "<name>"
(import_statement
  (import_clause
    (namespace_import
        "*"
        "as"
        (identifier) @imported_as))
  "from"
  source: (string (string_fragment) @name))

; const <imported_as> = require('<name>')
(lexical_declaration
  kind: "const"
  (variable_declarator
    name: (identifier) @imported_as
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
    pub fn new() -> Self {
        let query = tree_sitter::Query::new(
            &get_tree_sitter_language(&Language::JavaScript),
            JS_IMPORTS_QUERY,
        )
        .expect("query has valid syntax");

        Self {
            query,
            code: None,
            tree: None,
            cached_nodes: None,
        }
    }

    pub fn update_state(&mut self, tree: &tree_sitter::Tree, code: Arc<str>) {
        self.tree = Some(tree.clone());
        self.code = Some(code);
        self.cached_nodes = None;
    }

    pub fn fetch_nodes(
        &mut self,
        scope: &mut HandleScope,
    ) -> Result<Rc<MirroredVec<PackageImport, JSPackageImport<Class>>>, DDSAJsRuntimeError> {
        if let Some(cached_nodes) = &self.cached_nodes {
            return Ok(cached_nodes.clone());
        }

        let mut query_cursor = tree_sitter::QueryCursor::new();
        let mut array = MirroredVec::new(JSPackageImport::try_new(scope).unwrap(), scope);

        let (Some(tree), Some(code)) = (self.tree.as_ref(), self.code.as_ref()) else {
            array.set_data(scope, vec![]);
            return Ok(Rc::new(array));
        };

        // Transforms a JavaScript import into the module name
        // This will take the file stem path and remove the file extension if any
        //
        // e.g. './foo/bar.js' -> 'bar'
        let normalize_path = |s: &str| -> String {
            std::path::Path::new(s)
                .file_stem()
                .unwrap()
                .to_str()
                .unwrap()
                .to_string()
        };

        let query_result = query_cursor.matches(&self.query, tree.root_node(), code.as_bytes());
        let imports = query_result
            .into_iter()
            .map(|query_match| {
                let mut name = None;
                let mut imported_from = None;
                let mut imported_as = None;
                let mut has_default = false;

                for capture in query_match.captures {
                    let start = capture.node.byte_range().start;
                    let end = capture.node.byte_range().end;
                    let capture_name = self.query.capture_names()[capture.index as usize];
                    match capture_name {
                        "name" => name = Some(normalize_path(code.get(start..end).unwrap())),
                        "imported_as" => {
                            imported_as = Some(code.get(start..end).unwrap().to_string())
                        }
                        "name_except_default" => {
                            let as_text = code.get(start..end).unwrap();
                            if as_text == "default" {
                                has_default = true;
                            }
                            name = Some(as_text.to_string());
                        }
                        "imported_from" => {
                            imported_from = Some(normalize_path(code.get(start..end).unwrap()))
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

                PackageImport {
                    name: name.unwrap(),
                    imported_from,
                    imported_as,
                }
            })
            .collect::<Vec<_>>();

        array.set_data(scope, imports);

        let array = Rc::new(array);
        self.cached_nodes = Some(array.clone());
        Ok(array)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::{ddsa_lib::test_utils::cfg_test_runtime, tree_sitter::get_tree};

    #[test]
    fn test_get_js_imports() {
        let mut runtime = cfg_test_runtime();
        let scope = &mut runtime.handle_scope();
        let mut ctx_js = FileContextJavaScript::new();

        struct TestCase {
            code: &'static str,
            expected: Vec<PackageImport>,
        }

        let tests = [
            // import
            TestCase {
                code: r#"
                    import './foo/bar.js';
                    "#,
                expected: vec![PackageImport {
                    name: "bar".to_string(),
                    imported_from: None,
                    imported_as: None,
                }],
            },
            TestCase {
                code: r#"
                    import { foo } from './module1/file1.js';
                    import { bar as baz } from './module2/file2.js';
                    "#,
                expected: vec![
                    PackageImport {
                        name: "foo".to_string(),
                        imported_from: Some("file1".to_string()),
                        imported_as: None,
                    },
                    PackageImport {
                        name: "bar".to_string(),
                        imported_from: Some("file2".to_string()),
                        imported_as: Some("baz".to_string()),
                    },
                ],
            },
            TestCase {
                code: r#"
                    import foo from './module1/file1.js';
                    import bar from './module2/file2.js';
                    "#,
                expected: vec![
                    PackageImport {
                        name: "foo".to_string(),
                        imported_from: Some("file1".to_string()),
                        imported_as: None,
                    },
                    PackageImport {
                        name: "bar".to_string(),
                        imported_from: Some("file2".to_string()),
                        imported_as: None,
                    },
                ],
            },
            TestCase {
                code: r#"
                    import * as fs2 from "fs";
                    "#,
                expected: vec![PackageImport {
                    name: "fs".to_string(),
                    imported_from: None,
                    imported_as: Some("fs2".to_string()),
                }],
            },
            TestCase {
                code: r#"
                    import foo, { bar, baz } from './module1/file1.js';
                    "#,
                expected: vec![
                    PackageImport {
                        name: "bar".to_string(),
                        imported_from: Some("file1".to_string()),
                        imported_as: None,
                    },
                    PackageImport {
                        name: "baz".to_string(),
                        imported_from: Some("file1".to_string()),
                        imported_as: None,
                    },
                    PackageImport {
                        name: "foo".to_string(),
                        imported_from: Some("file1".to_string()),
                        imported_as: None,
                    },
                ],
            },
            // require
            TestCase {
                code: r#"
                    const fs = require('fs');
                    "#,
                expected: vec![PackageImport {
                    name: "fs".to_string(),
                    imported_from: None,
                    imported_as: Some("fs".to_string()),
                }],
            },
            TestCase {
                code: r#"
                    const { foo } = require('./module1/file1.js');
                    const { bar } = require('./module2/file2.js');
                    const { baz, qux } = require('./module3/file3.js');
                    "#,
                expected: vec![
                    PackageImport {
                        name: "foo".to_string(),
                        imported_from: Some("file1".to_string()),
                        imported_as: None,
                    },
                    PackageImport {
                        name: "bar".to_string(),
                        imported_from: Some("file2".to_string()),
                        imported_as: None,
                    },
                    PackageImport {
                        name: "baz".to_string(),
                        imported_from: Some("file3".to_string()),
                        imported_as: None,
                    },
                    PackageImport {
                        name: "qux".to_string(),
                        imported_from: Some("file3".to_string()),
                        imported_as: None,
                    },
                ],
            },
            // dynamic import
            TestCase {
                code: r#"
                    const foo = await import('./module1/file1.js');
                    "#,
                expected: vec![PackageImport {
                    name: "foo".to_string(),
                    imported_from: Some("file1".to_string()),
                    imported_as: None,
                }],
            },
            TestCase {
                code: r#"
                    const { bar } = await import('./module2/file2.js');
                    "#,
                expected: vec![PackageImport {
                    name: "bar".to_string(),
                    imported_from: Some("file2".to_string()),
                    imported_as: None,
                }],
            },
        ];

        for test in tests {
            let tree = get_tree(test.code, &Language::JavaScript).unwrap();
            ctx_js.update_state(&tree, Arc::from(test.code));
            let imports = ctx_js.fetch_nodes(scope).unwrap();
            assert_eq!(imports.len(), test.expected.len());

            for (idx, expected) in test.expected.iter().enumerate() {
                let actual = imports.get(idx).unwrap();
                assert_eq!(actual, expected);
            }

            let global_array = imports.v8_array();
            let local_array = global_array.open(scope);
            let import_ptr = local_array as *const _;

            {
                let imports2 = ctx_js.fetch_nodes(scope).unwrap();
                let global_array2 = imports2.v8_array();
                let local_array2 = global_array2.open(scope);
                let import_ptr2 = local_array2 as *const _;

                // Test that caching works
                assert_eq!(import_ptr, import_ptr2);
            }

            ctx_js.update_state(&tree, Arc::from(test.code));

            {
                let imports2 = ctx_js.fetch_nodes(scope).unwrap();
                let global_array2 = imports2.v8_array();
                let local_array2 = global_array2.open(scope);
                let import_ptr2 = local_array2 as *const _;

                // Test that caching does not work after updating the state
                assert_ne!(import_ptr, import_ptr2);
            }
        }
    }
}
