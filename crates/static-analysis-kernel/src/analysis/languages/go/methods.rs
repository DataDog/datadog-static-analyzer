// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::analysis::languages::ts_node_text;
use crate::analysis::tree_sitter::get_tree;
use crate::model::common::Language;
use crate::model::violation::EnclosingFunction;

/// Returns the enclosing function or method for the given source position, or `None` if the
/// position is not inside any function.
///
/// This function parses the source code from scratch.
/// If you already have a parsed tree, use [`find_enclosing_function_with_tree`].
pub fn find_enclosing_function(
    source_code: &str,
    line: u32,
    col: u32,
) -> Option<EnclosingFunction> {
    get_tree(source_code, &Language::Go)
        .and_then(|tree| find_enclosing_function_with_tree(source_code, &tree, line, col))
}

/// Returns the enclosing function or method for the given source position.
/// See [`find_enclosing_function`] for documentation.
///
/// The `fullyQualifiedName` follows the godoc / `go/types` convention:
///   - Package-level function: `packageName.FunctionName`
///   - Method on a type: `packageName.TypeName.MethodName`
///
/// Pointer receivers (`*Server`) are stripped to their base type (`Server`),
/// consistent with how godoc presents method documentation.
pub fn find_enclosing_function_with_tree(
    source_code: &str,
    tree: &tree_sitter::Tree,
    line: u32,
    col: u32,
) -> Option<EnclosingFunction> {
    let point = tree_sitter::Point {
        row: line.saturating_sub(1) as usize,
        column: col.saturating_sub(1) as usize,
    };
    let mut node = tree
        .root_node()
        .named_descendant_for_point_range(point, point)?;
    loop {
        match node.kind() {
            "function_declaration" => {
                let name = node
                    .child_by_field_name("name")
                    .map(|n| ts_node_text(source_code, n).to_owned())?;
                let package = find_package(source_code, tree.root_node());
                let fully_qualified_name = match package.as_deref() {
                    Some(pkg) => format!("{pkg}.{name}"),
                    None => name.clone(),
                };
                return Some(EnclosingFunction {
                    name,
                    fully_qualified_name,
                });
            }
            "method_declaration" => {
                let name = node
                    .child_by_field_name("name")
                    .map(|n| ts_node_text(source_code, n).to_owned())?;
                let package = find_package(source_code, tree.root_node());
                let receiver_type = extract_receiver_type(source_code, node);
                let fully_qualified_name = match (package.as_deref(), receiver_type.as_deref()) {
                    (Some(pkg), Some(recv)) => format!("{pkg}.{recv}.{name}"),
                    (None, Some(recv)) => format!("{recv}.{name}"),
                    (Some(pkg), None) => format!("{pkg}.{name}"),
                    (None, None) => name.clone(),
                };
                return Some(EnclosingFunction {
                    name,
                    fully_qualified_name,
                });
            }
            _ => {}
        }
        node = node.parent()?;
    }
}

/// Returns the package name declared at the top of the Go source file.
fn find_package(source_code: &str, root: tree_sitter::Node) -> Option<String> {
    for i in 0..root.named_child_count() {
        let Some(child) = root.named_child(i) else {
            continue;
        };
        if child.kind() == "package_clause" {
            // package_identifier is the only named child of package_clause
            return child
                .named_child(0)
                .filter(|n| n.kind() == "package_identifier")
                .map(|n| ts_node_text(source_code, n).to_owned());
        }
    }
    None
}

/// Extracts the receiver type name from a `method_declaration` node.
/// Pointer receivers (`*Server`) are unwrapped to their base type (`Server`)
/// to match the godoc URL and documentation format.
fn extract_receiver_type(source_code: &str, method_node: tree_sitter::Node) -> Option<String> {
    let receiver_list = method_node.child_by_field_name("receiver")?;
    for i in 0..receiver_list.named_child_count() {
        let Some(param_decl) = receiver_list.named_child(i) else {
            continue;
        };
        if param_decl.kind() == "parameter_declaration" {
            if let Some(type_node) = param_decl.child_by_field_name("type") {
                return match type_node.kind() {
                    // *Server → "Server"
                    "pointer_type" => type_node
                        .named_child(0)
                        .map(|n| ts_node_text(source_code, n).to_owned()),
                    _ => Some(ts_node_text(source_code, type_node).to_owned()),
                };
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::find_enclosing_function_with_tree;
    use crate::analysis::tree_sitter::get_tree;
    use crate::model::common::Language;
    use crate::model::violation::EnclosingFunction;

    fn find(source: &str, line: u32, col: u32) -> Option<EnclosingFunction> {
        let tree = get_tree(source, &Language::Go).unwrap();
        find_enclosing_function_with_tree(source, &tree, line, col)
    }

    fn ef(name: &str, sig: &str) -> Option<EnclosingFunction> {
        Some(EnclosingFunction {
            name: name.to_string(),
            fully_qualified_name: sig.to_string(),
        })
    }

    #[test]
    fn inside_function() {
        let src = "\
package main

func greet() {
    x := 1
}
";
        assert_eq!(find(src, 4, 5), ef("greet", "main.greet"));
    }

    #[test]
    fn inside_method_with_receiver() {
        let src = "\
package main

type Server struct{}

func (s *Server) Handle() {
    x := 1
}
";
        assert_eq!(find(src, 6, 5), ef("Handle", "main.Server.Handle"));
    }

    #[test]
    fn value_receiver() {
        let src = "\
package myapp

type Counter struct{}

func (c Counter) Increment() {
    x := 1
}
";
        assert_eq!(find(src, 5, 5), ef("Increment", "myapp.Counter.Increment"));
    }

    #[test]
    fn top_level_var() {
        let src = "\
package main

var x = 1
";
        assert_eq!(find(src, 3, 5), None);
    }
}
