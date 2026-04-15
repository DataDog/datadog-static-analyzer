// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::analysis::languages::ts_node_text;
use crate::analysis::tree_sitter::get_tree;
use crate::model::common::Language;

/// Returns the name of the innermost function or method enclosing the given source position,
/// or `None` if the position is not inside any named function.
///
/// This function parses the source code from scratch.
/// If you already have a parsed tree, use [`find_enclosing_function_with_tree`].
pub fn find_enclosing_function(source_code: &str, line: u32, col: u32) -> Option<String> {
    get_tree(source_code, &Language::JavaScript)
        .and_then(|tree| find_enclosing_function_with_tree(source_code, &tree, line, col))
}

/// Returns the name of the innermost function or method enclosing the given source position.
/// See [`find_enclosing_function`] for documentation.
///
/// Handles:
/// - `function foo() {}` → `"foo"`
/// - `class C { foo() {} }` → `"foo"`
/// - `const foo = function() {}` → `"foo"` (name from the variable declarator)
/// - `const foo = () => {}` → `"foo"` (name from the variable declarator)
/// - `const foo = function bar() {}` → `"bar"` (explicit name takes priority)
/// - Anonymous functions and arrow functions not assigned to a variable → `None`
pub fn find_enclosing_function_with_tree(
    source_code: &str,
    tree: &tree_sitter::Tree,
    line: u32,
    col: u32,
) -> Option<String> {
    let point = tree_sitter::Point {
        row: line.saturating_sub(1) as usize,
        column: col.saturating_sub(1) as usize,
    };
    let mut node = tree
        .root_node()
        .named_descendant_for_point_range(point, point)?;
    loop {
        match node.kind() {
            "function_declaration" | "generator_function_declaration" => {
                return node
                    .child_by_field_name("name")
                    .map(|n| ts_node_text(source_code, n).to_owned());
            }
            "method_definition" => {
                // Class method: `foo() {}` or `async foo() {}`
                return node
                    .child_by_field_name("name")
                    .map(|n| ts_node_text(source_code, n).to_owned());
            }
            // tree-sitter-javascript uses "function" for both anonymous function expressions
            // (`const f = function() {}`) and named function expressions (`const f = function g() {}`).
            // "function_declaration" is used only for statement-level `function foo() {}`.
            "function" | "generator_function" => {
                // Named function expression: `const x = function myName() {}`
                if let Some(name_node) = node.child_by_field_name("name") {
                    return Some(ts_node_text(source_code, name_node).to_owned());
                }
                // Anonymous function assigned to a variable: `const foo = function() {}`
                return name_from_variable_declarator_parent(source_code, node);
            }
            "arrow_function" => {
                // Arrow function assigned to a variable: `const foo = () => {}`
                return name_from_variable_declarator_parent(source_code, node);
            }
            _ => {}
        }
        node = node.parent()?;
    }
}

/// If `node`'s parent is a `variable_declarator`, returns the declarator's name.
fn name_from_variable_declarator_parent<'a>(
    source_code: &'a str,
    node: tree_sitter::Node<'a>,
) -> Option<String> {
    let parent = node.parent()?;
    if parent.kind() == "variable_declarator" {
        parent
            .child_by_field_name("name")
            .map(|n| ts_node_text(source_code, n).to_owned())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::{find_enclosing_function, find_enclosing_function_with_tree};
    use crate::analysis::tree_sitter::get_tree;
    use crate::model::common::Language;

    fn find(source: &str, line: u32, col: u32) -> Option<String> {
        let tree = get_tree(source, &Language::JavaScript).unwrap();
        find_enclosing_function_with_tree(source, &tree, line, col)
    }

    #[test]
    fn inside_function_declaration() {
        let src = "\
function greet() {
    const x = 1;
}
";
        assert_eq!(find(src, 2, 5), Some("greet".to_string()));
    }

    #[test]
    fn inside_class_method() {
        let src = "\
class MyClass {
    compute() {
        return 42;
    }
}
";
        assert_eq!(find(src, 3, 9), Some("compute".to_string()));
    }

    #[test]
    fn inside_arrow_function_assigned_to_const() {
        let src = "\
const handleEvent = () => {
    const x = 1;
};
";
        assert_eq!(find(src, 2, 5), Some("handleEvent".to_string()));
    }

    #[test]
    fn inside_anonymous_function_assigned_to_var() {
        let src = "\
const process = function() {
    const x = 1;
};
";
        assert_eq!(find(src, 2, 5), Some("process".to_string()));
    }

    #[test]
    fn named_function_expression_uses_explicit_name() {
        let src = "\
const x = function myFn() {
    const y = 1;
};
";
        assert_eq!(find(src, 2, 5), Some("myFn".to_string()));
    }

    #[test]
    fn top_level_code() {
        let src = "const x = 1;\n";
        assert_eq!(find(src, 1, 1), None);
    }

    #[test]
    fn anonymous_arrow_not_assigned() {
        let src = "\
[1, 2].map(() => {
    return 0;
});
";
        assert_eq!(find(src, 2, 5), None);
    }
}
