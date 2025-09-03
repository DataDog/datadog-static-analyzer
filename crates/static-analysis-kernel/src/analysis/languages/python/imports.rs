// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::analysis::languages::ts_node_text;
use crate::analysis::tree_sitter::{get_tree, get_tree_sitter_language};
use crate::model::common::Language;
use std::sync::LazyLock;
use streaming_iterator::StreamingIterator;

//
// Note: Dynamic imports like `__import__(...)` and `importlib.import_module(...)` have not been implemented.
//

/// Metadata about a statically imported module from a Python source file.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Import<'a> {
    full_text: &'a str,
    pub alias: Option<&'a str>,
    pub entities: Option<ImportEntities<'a>>,
    pub is_relative: bool,
}

impl<'a> Import<'a> {
    /// Creates a new [`Import`].
    pub fn try_new(
        full_text: &'a str,
        alias: Option<&'a str>,
        entities: Option<ImportEntities<'a>>,
        is_relative: bool,
    ) -> Result<Import<'a>, String> {
        // We need to first validate that the `full_text` has no whitespace.
        //
        // (This is necessary because the tree-sitter-python grammar currently allows the creation
        // of valid `dotted_name` CST nodes that represent invalid python). For example:
        //
        // ```py
        // import numpy.
        // # comment
        // random
        // ```
        //
        // results in the following valid tree:
        // ```text
        // import_statement [0, 0] - [2, 6]
        //     name: dotted_name [0, 7] - [2, 6]
        //       identifier [0, 7] - [0, 12]
        //       comment [1, 0] - [1, 9]
        //       identifier [2, 0] - [2, 6]
        // ```
        if full_text.contains(char::is_whitespace) {
            Err(format!(
                "expected string without whitespace, got: \"{full_text}\""
            ))
        } else {
            Ok(Import {
                full_text,
                alias,
                entities,
                is_relative,
            })
        }
    }

    /// Returns the direct name of the import.
    ///
    /// # Examples
    /// ```py
    /// import tensorflow.keras.layers # "layers"
    /// import tensorflow # "tensorflow"
    /// from ..common_utils import parse_config # "common_utils"
    /// from ..common_utils.local_utils import parse_config # "local_utils"
    /// ```
    pub fn name(&self) -> &str {
        self.full_text
            .rsplit_once('.')
            .map(|(_, name)| name)
            .unwrap_or(self.full_text)
    }

    /// Returns the fully-qualified name of the entity. This will only be `None` for a relative import.
    ///
    /// # Examples
    /// ```py
    /// import tensorflow.keras.layers # `Some("tensorflow.keras.layers")`
    /// from ..common_utils import parse_config # `None`
    /// ```
    pub fn fully_qualified_name(&self) -> Option<&str> {
        (!self.is_relative).then_some(self.full_text)
    }

    /// Returns the parent module for this entity, if it exists. Relative imports are only
    /// considered to have a parent module if that module is specified in the import (and
    /// thus not implicit from the file system hierarchy)
    ///
    /// Note that this function only interprets the underlying string slice -- no actual
    /// module resolution is performed.
    ///
    /// # Examples
    /// ```py
    /// import tensorflow.keras.layers # Some(Import("tensorflow.keras"))
    /// import tensorflow # None
    /// from ..common_utils import parse_config # None
    /// from ..common_utils.local_utils import print_array # Some(Import("common_utils"))
    /// ```
    pub fn parent_import(&self) -> Option<Import<'a>> {
        self.full_text.rsplit_once('.').and_then(|(parent, _)| {
            let import = Import::try_new(parent, None, None, self.is_relative);
            debug_assert!(import.is_ok());
            import.ok()
        })
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum ImportEntities<'a> {
    /// An indicator that everything from a module is being imported.
    /// ```py
    /// from numpy.random import *
    /// ```
    Wildcard,
    /// A specific list of entities to import from a module:
    /// ```py
    /// from numpy.random import chisquare, poisson
    /// ```
    /// In the above case, there will be an `Entity` for "chisquare", and an `Entity` for "poisson".
    Specific(Vec<Entity<'a>>),
}

/// An entity brought into scope via an import.
///
/// # Examples
/// ```py
/// from numpy import cos as c # Entity { name: "cos", alias: Some("c") }
/// from numpy import tan # Entity { name: "tan", alias: None }
/// ```
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct Entity<'a> {
    pub name: &'a str,
    pub alias: Option<&'a str>,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
/// An intermediate struct to hold the result of parsing either an entity or module specification.
struct MaybeAliased<'a> {
    /// Text that could either be a single identifier (e.g. "tensorflow"), or a
    /// fully-qualified identifier (e.g. "tensorflow.keras.layers")
    pub full_text: &'a str,
    pub alias: Option<&'a str>,
}

/// Returns the static imports in the provided Python source code as a list, which is ordered by line ascending.
///
/// This function parses the source code from scratch.
/// If you already have a parsed tree, you should use [`parse_imports_with_tree`].
pub fn parse_imports(source_code: &str) -> Vec<Import> {
    get_tree(source_code, &Language::Python)
        .map(|tree| parse_imports_with_tree(source_code, &tree))
        .unwrap_or_default()
}

/// Returns the static imports for the provided parse tree. See [`parse_imports`] for documentation.
pub fn parse_imports_with_tree<'text>(
    source_code: &'text str,
    tree: &tree_sitter::Tree,
) -> Vec<Import<'text>> {
    parse_static_imports(source_code, tree)
}

const FIELD_EXISTS: &str = "tree-sitter grammar invariant: field name should exist";

/// Returns a list of all imports in the provided tree. Invalidly-specified imports are silently dropped.
fn parse_static_imports<'text>(
    source_code: &'text str,
    tree: &tree_sitter::Tree,
) -> Vec<Import<'text>> {
    static TS_QUERY: LazyLock<tree_sitter::Query> = LazyLock::new(|| {
        let query_string = r#"
[
    (import_statement)
    (import_from_statement)
    (future_import_statement)
] @import
    "#;

        tree_sitter::Query::new(&get_tree_sitter_language(&Language::Python), query_string)
            .expect("query should have valid syntax")
    });

    let mut imports = Vec::<Import>::new();
    let mut query_cursor = tree_sitter::QueryCursor::new();
    let mut query_result =
        query_cursor.matches(&TS_QUERY, tree.root_node(), source_code.as_bytes());

    while let Some(query_match) = query_result.next() {
        let import_node = query_match
            .captures
            .first()
            .expect("query invariant: should have exactly 1 capture")
            .node;

        match import_node.kind() {
            "import_statement" => {
                imports.extend(parse_import_statement(source_code, import_node));
            }
            "import_from_statement" => {
                if let Ok(import) = parse_import_from_statement(source_code, import_node) {
                    imports.push(import);
                }
            }
            "future_import_statement" => {
                if let Ok(import) = parse_future_import_statement(source_code, import_node) {
                    imports.push(import);
                }
            }
            _ => unreachable!(),
        }
    }
    imports
}

/// Returns all imports from the provided `import_statement` node.
///
/// Invalidly-specified imports are silently ignored.
fn parse_import_statement<'tree, 'text: 'tree>(
    source_code: &'text str,
    node: tree_sitter::Node<'tree>,
) -> impl Iterator<Item = Import<'text>> + 'tree {
    debug_assert_eq!(node.kind(), "import_statement");
    let mut idx = 0;
    std::iter::from_fn(move || {
        // We loop so that if creating the `Import` fails, we can try any subsequent imports within
        // this node (e.g. in a comma-separated list) to avoid prematurely yielding `None` on the iterator.
        while idx < node.named_child_count() {
            debug_assert_eq!(node.field_name_for_named_child(idx as u32), Some("name"));
            let name_node = node.named_child(idx).expect("should be in-bounds");
            let parsed = parse_field_child_node(source_code, name_node);

            idx += 1;

            if let Ok(import) = Import::try_new(parsed.full_text, parsed.alias, None, false) {
                return Some(import);
            }
        }
        None
    })
}

/// Returns an import from the provided `import_from_statement` node.
fn parse_import_from_statement<'text>(
    source_code: &'text str,
    node: tree_sitter::Node,
) -> Result<Import<'text>, String> {
    debug_assert_eq!(node.kind(), "import_from_statement");
    let module_name_node = node.child_by_field_name("module_name").expect(FIELD_EXISTS);
    let is_relative = module_name_node.kind() == "relative_import";
    let parsed_module = parse_field_child_node(source_code, module_name_node);
    // Python syntax invariant: the module of a "from" import can't have an alias.
    debug_assert!(parsed_module.alias.is_none());
    // tree-sitter grammar invariant: a valid wildcard import must end in a `wildcard_import` node.
    let entities = if node
        .child(node.child_count() - 1)
        .is_some_and(|n| n.kind() == "wildcard_import")
    {
        ImportEntities::Wildcard
    } else {
        // Collect all the imports belonging to this module:
        let mut cursor = node.walk();
        let field_children = node.children_by_field_name("name", &mut cursor);
        let entities = field_children
            .into_iter()
            .map(|child| {
                let parsed = parse_field_child_node(source_code, child);
                // tree-sitter grammar invariant: these children represent entities, never a module.
                Entity {
                    name: parsed.full_text,
                    alias: parsed.alias,
                }
            })
            .collect::<Vec<_>>();
        ImportEntities::Specific(entities)
    };
    Import::try_new(
        parsed_module.full_text,
        parsed_module.alias,
        Some(entities),
        is_relative,
    )
}

/// Returns an import from the provided `future_import_statement` node.
fn parse_future_import_statement<'text>(
    source_code: &'text str,
    node: tree_sitter::Node,
) -> Result<Import<'text>, String> {
    debug_assert_eq!(node.kind(), "future_import_statement");
    let mut cursor = node.walk();
    let field_children = node.children_by_field_name("name", &mut cursor);
    let entities = field_children
        .into_iter()
        .map(|child| {
            let parsed = parse_field_child_node(source_code, child);
            // tree-sitter grammar invariant: these children represent entities, never a module.
            Entity {
                name: parsed.full_text,
                alias: parsed.alias,
            }
        })
        .collect::<Vec<_>>();
    Import::try_new(
        // `__future__` is special-cased by the compiler, so we also manually specify it here.
        // See: https://docs.python.org/3/library/__future__.html
        "__future__",
        None,
        Some(ImportEntities::Specific(entities)),
        false,
    )
}

/// Constructs a [`MaybeAliased`] from the provided `node`. This is intended to be used on
/// the `name` and `module_name` field children.
///
/// # Panics
/// Panics if the provided node isn't a:
/// * `dotted_name`
/// * `aliased_import`
/// * `relative_import`
fn parse_field_child_node<'text>(
    source_code: &'text str,
    node: tree_sitter::Node,
) -> MaybeAliased<'text> {
    match node.kind() {
        "relative_import" => {
            // (relative_import (import_prefix) (dotted_name))
            for i in 0..node.child_count() {
                let child = node.child(i).expect("i should be in-bounds");
                if child.kind() == "dotted_name" {
                    return MaybeAliased {
                        full_text: ts_node_text(source_code, child),
                        alias: None,
                    };
                }
            }
            // Otherwise, this `relative_import` only contains an `import_prefix` node,
            // so return the entire node's text (which will consist of one or more "."):
            MaybeAliased {
                full_text: ts_node_text(source_code, node),
                alias: None,
            }
        }
        "dotted_name" => {
            // (dotted_name (identifier)+)
            MaybeAliased {
                full_text: ts_node_text(source_code, node),
                alias: None,
            }
        }
        "aliased_import" => {
            // (aliased_import name: (dotted_name) alias: (identifier))
            let name_node = node.child_by_field_name("name").expect(FIELD_EXISTS);
            let full_text = ts_node_text(source_code, name_node);
            debug_assert_eq!(name_node.kind(), "dotted_name");
            let alias_node = node.child_by_field_name("alias").expect(FIELD_EXISTS);
            debug_assert_eq!(alias_node.kind(), "identifier");
            let alias = ts_node_text(source_code, alias_node);
            MaybeAliased {
                full_text,
                alias: Some(alias),
            }
        }
        other => panic!("invalid node type `{other}`"),
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_imports, Entity, Import, ImportEntities};

    /// A shorthand to build an [`Entity`] without an alias.
    pub fn ent(name: &str) -> Entity {
        Entity { name, alias: None }
    }

    /// A shorthand to build an [`Entity`] with an alias.
    fn alias<'a>(name: &'a str, alias: &'a str) -> Entity<'a> {
        let alias = Some(alias);
        Entity { name, alias }
    }

    /// Functions that slice strings to provide relationship metadata work correctly.
    #[test]
    fn import_text_based_metadata() {
        // Structure for test cases:
        // `(fully_qualified_name, (expected_parent_import, expected_import_name))`

        // Absolute imports
        #[rustfmt::skip]
        let absolutes = {
            vec![
                ("tensorflow", (None, "tensorflow")),
                ("tensorflow.keras", (Some("tensorflow"), "keras")),
                ("tensorflow.keras.layers", (Some("tensorflow.keras"), "layers")),
            ]
        };
        // Relative imports
        #[rustfmt::skip]
        let relatives = {
            vec![
                ("local_utils", (None, "local_utils")),
                ("common_utils.local_utils", (Some("common_utils"), "local_utils")),
            ]
        };

        for (cases, is_relative) in [(absolutes, false), (relatives, true)] {
            for (full_text, (expected_parent, expected_name)) in cases {
                let this_import = Import::try_new(full_text, None, None, is_relative).unwrap();
                let expected_fqn = (!is_relative).then_some(full_text);
                assert_eq!(this_import.fully_qualified_name(), expected_fqn);
                assert_eq!(this_import.name(), expected_name);
                let expected_parent_import = expected_parent.map(|parent_text| {
                    Import::try_new(parent_text, None, None, is_relative).unwrap()
                });
                assert_eq!(this_import.parent_import(), expected_parent_import);
            }
        }
    }

    /// (See documentation on [`Import::try_new`] for why this behavior (and thus test) is necessary.
    #[test]
    fn new_import_no_whitespace() {
        assert!(Import::try_new("numpy.random", None, None, false).is_ok());
        assert!(Import::try_new("numpy.\nrandom", None, None, false).is_err());
    }

    #[test]
    fn parse_static_imports() {
        use ImportEntities::{Specific, Wildcard};
        // Absolute imports
        #[rustfmt::skip]
        let absolutes = {
            vec![
                ("import numpy", ("numpy", None, None)),
                ("import numpy.random.mtrand", ("numpy.random.mtrand", None, None)),
                ("from numpy import *", ("numpy", None, Some(Wildcard))),
                ("from numpy.core import ndarray", ("numpy.core", None, Some(Specific(vec![ent("ndarray")])))),
                ("from numpy import cos, tan", ("numpy", None, Some(Specific(vec![ent("cos"), ent("tan")])))),
                ("import numpy as np", ("numpy", Some("np"), None)),
                ("from numpy import fliplr as flip_leftright", ("numpy", None, Some(Specific(vec![alias("fliplr", "flip_leftright")])))),
                ("from numpy import cos as c, tan", ("numpy", None, Some(Specific(vec![alias("cos", "c"), ent("tan")])))),
                ("from __future__ import annotations, division", ("__future__", None, Some(Specific(vec![ent("annotations"), ent("division")]))))
            ]
        };

        // Relative imports
        #[rustfmt::skip]
        let relatives = {
            vec![
                ("from ..common_utils import parse_config", ("common_utils", None, Some(Specific(vec![ent("parse_config")])))),
                ("from ..common_utils.local_utils import print_array as print", ("common_utils.local_utils", None, Some(Specific(vec![alias("print_array", "print")])))),
                ("from .local_utils import *", ("local_utils", None, Some(Wildcard))),
                ("from . import *", (".", None, Some(Wildcard))),
                ("from .. import *", ("..", None, Some(Wildcard))),
            ]
        };

        for (cases, is_relative) in [(absolutes, false), (relatives, true)] {
            for (py_code, (expected_module_text, expected_alias, expected_entities)) in cases {
                let expected_import = Import::try_new(
                    expected_module_text,
                    expected_alias,
                    expected_entities,
                    is_relative,
                )
                .unwrap();
                let actual_imports = parse_imports(py_code);
                assert_eq!(actual_imports, vec![expected_import]);
            }
        }
    }
}

/// mod for documenting (intentionally) "incorrect" parsing behavior.
#[cfg(test)]
mod limitations {
    use super::tests::ent;
    use super::{parse_imports, Import, ImportEntities};

    /// Dynamic import parsing logic has not been implemented.
    #[test]
    fn unimplemented_dynamic_imports() {
        use ImportEntities::Specific;

        // Only static imports will be reported.
        #[rustfmt::skip]
        let cases = {
            [
                ("np = __import__('numpy')", vec![]),
                ("import importlib\nnp = importlib.__import__('numpy')", vec![("importlib", None, None)]),
                ("import importlib\nnp = importlib.import_module('numpy')", vec![("importlib", None, None)]),
                ("from importlib import import_module\nnp = import_module('numpy')", vec![("importlib", None, Some(Specific(vec![ent("import_module")])))]),
            ]
        };
        for (py_code, imports) in cases {
            let expected_imports = imports
                .into_iter()
                .map(|expected| {
                    let (module_text, alias, entities) = expected;
                    Import::try_new(module_text, alias, entities, false).unwrap()
                })
                .collect::<Vec<_>>();
            let actual_imports = parse_imports(py_code);
            assert_eq!(actual_imports, expected_imports);
        }
    }
}
