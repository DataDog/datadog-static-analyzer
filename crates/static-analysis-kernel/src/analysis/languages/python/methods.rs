// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::analysis::languages::{enclosing_class_name, ts_node_text};
use crate::analysis::tree_sitter::get_tree;
use crate::model::common::Language;
use crate::model::violation::EnclosingFunction;

/// Returns the enclosing function for the given source position, or `None` if the position
/// is not inside any function.
///
/// This function parses the source code from scratch.
/// If you already have a parsed tree, use [`find_enclosing_function_with_tree`].
pub fn find_enclosing_function(source_code: &str, line: u32, col: u32) -> Option<EnclosingFunction> {
    get_tree(source_code, &Language::Python)
        .and_then(|tree| find_enclosing_function_with_tree(source_code, &tree, line, col))
}

/// Returns the enclosing function for the given source position.
/// See [`find_enclosing_function`] for documentation.
///
/// The `fullyQualifiedName` follows Python's `__qualname__` convention:
///   - Module-level function: `function_name`
///   - Method inside a class: `ClassName.method_name`
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
            "function_definition" | "async_function_definition" => {
                let name = node
                    .child_by_field_name("name")
                    .map(|n| ts_node_text(source_code, n).to_owned())?;
                let fully_qualified_name =
                    match enclosing_class_name(source_code, node, &["class_definition"]) {
                        Some(cls) => format!("{cls}.{name}"),
                        None => name.clone(),
                    };
                return Some(EnclosingFunction { name, fully_qualified_name });
            }
            _ => {}
        }
        node = node.parent()?;
    }
}

#[cfg(test)]
mod tests {
    use super::{find_enclosing_function, find_enclosing_function_with_tree};
    use crate::analysis::tree_sitter::get_tree;
    use crate::model::common::Language;
    use crate::model::violation::EnclosingFunction;

    fn find(source: &str, line: u32, col: u32) -> Option<EnclosingFunction> {
        let tree = get_tree(source, &Language::Python).unwrap();
        find_enclosing_function_with_tree(source, &tree, line, col)
    }

    fn find_no_tree(source: &str, line: u32, col: u32) -> Option<EnclosingFunction> {
        find_enclosing_function(source, line, col)
    }

    fn ef(name: &str, sig: &str) -> Option<EnclosingFunction> {
        Some(EnclosingFunction { name: name.to_string(), fully_qualified_name: sig.to_string() })
    }

    #[test]
    fn inside_function() {
        let src = "\
def greet():
    x = 1
";
        assert_eq!(find(src, 2, 5), ef("greet", "greet"));
    }

    #[test]
    fn inside_function_no_tree() {
        let src = "\
def greet():
    x = 1
";
        assert_eq!(find_no_tree(src, 2, 5), ef("greet", "greet"));
    }

    #[test]
    fn inside_method() {
        let src = "\
class MyClass:
    def compute(self):
        return 42
";
        assert_eq!(find(src, 3, 9), ef("compute", "MyClass.compute"));
    }

    #[test]
    fn inside_async_function() {
        let src = "\
async def fetch(url):
    return url
";
        assert_eq!(find(src, 2, 5), ef("fetch", "fetch"));
    }

    #[test]
    fn with_return_type_annotation() {
        let src = "\
def greet(x: int) -> str:
    return str(x)
";
        assert_eq!(find(src, 2, 5), ef("greet", "greet"));
    }

    #[test]
    fn nested_function_resolves_innermost() {
        let src = "\
def outer():
    def inner():
        x = 1
";
        assert_eq!(find(src, 3, 9), ef("inner", "inner"));
    }

    #[test]
    fn top_level_code() {
        let src = "x = 1\n";
        assert_eq!(find(src, 1, 1), None);
    }
}
