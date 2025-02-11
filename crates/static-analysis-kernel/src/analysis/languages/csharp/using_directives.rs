// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::analysis::languages::ts_node_text;
use crate::analysis::tree_sitter::{get_tree, get_tree_sitter_language};
use crate::model::common::Language;
use std::sync::LazyLock;
use streaming_iterator::StreamingIterator;

/// Structured information about a using directive import in a C# source file.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct Using<'a> {
    /// The name of the namespace.
    /// ```cs
    /// // Example:
    /// using System.IO;
    /// ```
    /// In the above example, `namespace` will be the text "System.IO".
    pub namespace: &'a str,
    /// An optional alias for a namespace being brought into scope.
    /// ```cs
    /// // Example:
    /// using InputOutput = System.IO;
    /// ```
    /// In the above example, `alias` will be the text "InputOutput".
    pub alias: Option<&'a str>,
}

/// Returns the using directives in the provided C# source code as a list, which is ordered by line ascending.
///
/// This function parses the source code from scratch.
/// If you already have a parsed tree, you should use [`parse_using_with_tree`].
pub fn parse_using(source_code: &str) -> Vec<Using> {
    get_tree(source_code, &Language::Csharp)
        .map(|tree| parse_using_with_tree(source_code, &tree))
        .unwrap_or_default()
}

/// Returns using directives for the provided parse tree. See [`parse_using`] for documentation.
pub fn parse_using_with_tree<'text>(
    source_code: &'text str,
    tree: &tree_sitter::Tree,
) -> Vec<Using<'text>> {
    static TS_QUERY: LazyLock<tree_sitter::Query> = LazyLock::new(|| {
        // We need to be able to distinguish `using_directive` nodes _with_ a "name" field child,
        // and those without them. This is much easier to achieve if we manually traverse the tree
        // due to negations in tree-sitter queries not being supported.
        let query_string = r#"
(using_directive) @using
    "#;

        tree_sitter::Query::new(&get_tree_sitter_language(&Language::Csharp), query_string)
            .expect("query should have valid syntax")
    });

    let mut usings = Vec::<Using>::new();
    let mut query_cursor = tree_sitter::QueryCursor::new();
    let mut query_result =
        query_cursor.matches(&TS_QUERY, tree.root_node(), source_code.as_bytes());
    while let Some(query_match) = query_result.next() {
        let mut alias: Option<&str> = None;
        let mut qualified_namespace: Option<&str> = None;
        // There are two main permutations:
        // ```cs
        // using System;
        // ^^^^^^^^^^^^ (using_directive [(identifier) (qualified_name) (alias_qualified_name)])
        // using Alias = System;
        // ^^^^^^^^^^^^^^^^^^^^ (using_directive [(identifier) (qualified_name) (alias_qualified_name)])
        // ```
        //
        // Within these, the "namespace" itself has six permutations:
        // ```cs
        // using System;
        //       ^^^^^^ (identifier)
        // using System.IO;
        //       ^^^^^^^^^ (qualified_name) with `qualifier: (identifier)`
        // using System.IO.Compression;
        //       ^^^^^^^^^^^^^^^^^^^^^ (qualified_name) with `qualifier: (qualified_name)` with `qualifier: (identifier)`
        //
        // -----------------------------------------------------------------------------------------
        // <Unimplemented>
        //
        // using SN::System;
        //       ^^^^^^^^^^ (alias_qualified_name)
        // using SN::System.IO;
        //       ^^^^^^^^^^^^^ (qualified_name) with `qualifier: (alias_qualified_name)`
        // using SN::System.IO.Compression;
        //       ^^^^^^^^^^^^^^^^^^^^^^^^^
        //       (qualified_name) with `qualifier: (qualified_name)` with `qualifier: (alias_qualified_name)`
        // ```

        // The query has exactly one capture
        debug_assert_eq!(query_match.captures[0].node.kind(), "using_directive");
        let captured_using = query_match.captures[0].node;

        let mut cursor = captured_using.walk();
        let children_iter = captured_using.children(&mut cursor);
        for (idx, node) in children_iter.enumerate() {
            // Check if this could be a `name` field child:
            if alias.is_none()
                && captured_using
                    .field_name_for_child(idx as u32)
                    .is_some_and(|f| f == "name")
            {
                let alias_text = ts_node_text(source_code, node);
                let _ = alias.insert(alias_text);
                continue;
            }

            match node.kind() {
                "identifier" => {
                    // Because we've already handled the `name` field child, this node _must_
                    // represent the text of the namespace.
                    let namespace_text = ts_node_text(source_code, node);
                    let _ = qualified_namespace.insert(namespace_text);
                    break;
                }
                "qualified_name" => {
                    let namespace_text = ts_node_text(source_code, node);
                    if namespace_text.contains("::") {
                        // Due to the recursive nature of the grammar nodes, we would need to recur
                        // into each `qualified_name` child to inspect the last one to determine if
                        // this is an (unsupported) `alias_qualified_name`.
                        //
                        // While less efficient, it's much easier to just match `::` in the text.
                        return vec![];
                    }
                    let _ = qualified_namespace.insert(namespace_text);
                    break;
                }
                "alias_qualified_name" => {
                    // Unimplemented
                    return vec![];
                }
                _ => {}
            }
        }

        // Hotfix:
        // The above parser does not handle cases like
        // using (var resource = new ResourceType())
        // {
        //     // ...
        // }
        //
        // In this case, we just set the qualified namespace to "".
        //
        // This should be revisited.
        let namespace = qualified_namespace.unwrap_or_default();
        usings.push(Using { namespace, alias })
    }
    usings
}

#[cfg(test)]
mod tests {
    use super::{parse_using, Using};

    #[test]
    fn parse_using_directives() {
        let source_code = "\
using System;                       // (using_directive (identifier))
using Alias = System;               // (using_directive name: (identifier) (identifier))
using System.IO;                    // (using_directive (qualified_name))
using Alias = System.IO;            // (using_directive name: (identifier) (qualified_name))
";
        let expected = [
            ("System", None),
            ("System", Some("Alias")),
            ("System.IO", None),
            ("System.IO", Some("Alias")),
        ]
        .into_iter()
        .map(|(namespace, alias)| Using { namespace, alias })
        .collect::<Vec<_>>();

        let actual = parse_using(source_code);
        assert_eq!(actual, expected);
    }
}

/// mod for documenting (intentionally) "incorrect" parsing behavior.
#[cfg(test)]
mod limitations {
    use super::parse_using;

    /// Parsing the [namespace alias operator] is unimplemented
    ///
    /// [namespace alias operator]: https://learn.microsoft.com/en-us/dotnet/csharp/language-reference/operators/namespace-alias-qualifier
    #[test]
    fn unimplemented_namespace_alias_operator() {
        let actual_imports = parse_using(
            "\
extern alias SN;
using SN::System;
using SN::System.IO;
using SN::System.IO.Compression;
",
        );
        assert!(actual_imports.is_empty());
    }
}
