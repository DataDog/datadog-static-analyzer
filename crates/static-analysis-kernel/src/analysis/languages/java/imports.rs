// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::analysis::languages::ts_node_text;
use crate::analysis::tree_sitter::{get_tree, get_tree_sitter_language};
use crate::model::common::Language;
use std::sync::LazyLock;
use streaming_iterator::StreamingIterator;

/// Structured information about an import in a Java source file.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct Import<'a> {
    /// The name of the package.
    /// ```java
    /// // Examples:
    /// import java.util.*;
    /// import java.util.Scanner;
    /// ```
    /// In both of the above examples, `package` will be the text "java.util".
    pub package: &'a str,
    /// ```java
    /// // Examples:
    /// import java.util.*;
    /// import java.util.Scanner;
    /// ```
    /// In the above examples, the target will be [`ImportTarget::Wildcard`] and
    /// [`ImportTarget::Class`], respectively.
    pub target: ImportTarget<'a>,
}

/// Metadata about the type of import within a Java package.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum ImportTarget<'a> {
    /// All classes from the provided package.
    /// ```java
    /// // Example:
    /// import java.util.*;
    /// ```
    Wildcard,
    /// A specific class within a package.
    /// ```java
    /// // Example:
    /// import java.util.Scanner;
    /// ```
    /// In the above example, the inner value of this variant will be the text "Scanner".
    Class(&'a str),
}

/// Returns the imports in the provided Java source code as a list, which is ordered by line ascending.
///
/// This function parses the source code from scratch.
/// If you already have a parsed tree, you should use [`parse_imports_with_tree`].
pub fn parse_imports(source_code: &str) -> Vec<Import> {
    get_tree(source_code, &Language::Java)
        .map(|tree| parse_imports_with_tree(source_code, &tree))
        .unwrap_or_default()
}

/// Returns imports for the provided parse tree. See [`parse_imports`] for documentation.
pub fn parse_imports_with_tree<'text>(
    source_code: &'text str,
    tree: &tree_sitter::Tree,
) -> Vec<Import<'text>> {
    static TS_QUERY: LazyLock<tree_sitter::Query> = LazyLock::new(|| {
        let query_string = r#"
(import_declaration
    [
        (identifier) @package
        (scoped_identifier scope: (_) @package name: (_) @class)
    ] @import_child
    .
    (asterisk)? @wildcard
)
    "#;

        tree_sitter::Query::new(&get_tree_sitter_language(&Language::Java), query_string)
            .expect("query should have valid syntax")
    });

    let mut imports = Vec::<Import>::new();
    let mut query_cursor = tree_sitter::QueryCursor::new();
    let mut query_result =
        query_cursor.matches(&TS_QUERY, tree.root_node(), source_code.as_bytes());
    while let Some(query_match) = query_result.next() {
        let mut package_node: Option<&str> = None;
        let mut target: Option<ImportTarget> = None;
        let mut import_child_node: Option<&str> = None;

        for capture in query_match.captures {
            let node_text = ts_node_text(source_code, capture.node);
            let capture_name = TS_QUERY.capture_names()[capture.index as usize];
            match capture_name {
                "package" => {
                    debug_assert!(package_node.is_none());
                    let _ = package_node.insert(node_text);
                }
                "class" => {
                    debug_assert_ne!(node_text, "*");
                    // We should never encounter a `Some` value in `target` here, but to be
                    // conservative, we can use `get_or_insert` to ensure we never overwrite a wildcard value.
                    let _ = target.get_or_insert(ImportTarget::Class(node_text));
                }
                "import_child" => {
                    debug_assert!(import_child_node.is_none());
                    let _ = import_child_node.insert(node_text);
                }
                "wildcard" => {
                    // We may have already populated `target` at this point -- we should overwrite it.
                    let _ = target.insert(ImportTarget::Wildcard);
                }
                _ => unreachable!(),
            }
        }

        let package_node = package_node.expect("query invariant: value should be Some");
        let target = target.expect("query invariant: value should be Some");
        // Due to the way the tree-sitter-java grammar is defined, when there is an asterisk, what
        // we've captured as the `import_child` will represent the full text of the package.
        // Otherwise, what we've captured as `package` will.
        let package = match target {
            ImportTarget::Wildcard => {
                import_child_node.expect("query invariant: value should be Some")
            }
            ImportTarget::Class(_) => package_node,
        };
        imports.push(Import { package, target });
    }
    imports
}

#[cfg(test)]
mod tests {
    use super::{parse_imports, Import, ImportTarget};

    #[test]
    fn import_parse_class() {
        let source_code = "\
import java.util.Scanner;
import java.util.Observable;
import javax.servlet.http.HttpServlet;
";
        let expected = [
            ("java.util", "Scanner"),
            ("java.util", "Observable"),
            ("javax.servlet.http", "HttpServlet"),
        ]
        .into_iter()
        .map(|(package, class)| Import {
            package,
            target: ImportTarget::Class(class),
        })
        .collect::<Vec<_>>();

        let actual = parse_imports(source_code);
        assert_eq!(actual, expected);
    }

    #[test]
    fn import_parse_wildcard() {
        let source_code = "\
import java.util.*;
import javax.servlet.http.*;
";
        let expected = ["java.util", "javax.servlet.http"]
            .into_iter()
            .map(|package| Import {
                package,
                target: ImportTarget::Wildcard,
            })
            .collect::<Vec<_>>();

        let actual = parse_imports(source_code);
        assert_eq!(actual, expected);
    }
}
