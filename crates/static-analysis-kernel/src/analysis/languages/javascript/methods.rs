// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::analysis::languages::{enclosing_class_name, ts_node_text};
use crate::analysis::tree_sitter::get_tree;
use crate::model::common::Language;
use crate::model::violation::EnclosingFunction;

/// Returns the enclosing function or method for the given source position, or `None` if the
/// position is not inside any named function.
///
/// This function parses the source code from scratch.
/// If you already have a parsed tree, use [`find_enclosing_function_with_tree`].
pub fn find_enclosing_function(
    source_code: &str,
    line: u32,
    col: u32,
) -> Option<EnclosingFunction> {
    get_tree(source_code, &Language::JavaScript)
        .and_then(|tree| find_enclosing_function_with_tree(source_code, &tree, line, col))
}

/// Returns the enclosing function or method for the given source position.
/// See [`find_enclosing_function`] for documentation.
///
/// The `fullyQualifiedName` follows the JavaScript/V8 convention:
///   - Top-level function: `functionName`
///   - Class instance method: `ClassName.methodName`
///   - Class static method: `ClassName.methodName`
///   - Arrow/anonymous function assigned to a variable: `variableName`
///   - Anonymous functions not assigned to a variable → `None`
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
            "function_declaration" | "generator_function_declaration" => {
                let name = node
                    .child_by_field_name("name")
                    .map(|n| ts_node_text(source_code, n).to_owned())?;
                let fully_qualified_name = name.clone();
                return Some(EnclosingFunction {
                    name,
                    fully_qualified_name,
                });
            }
            "method_definition" => {
                let name = node
                    .child_by_field_name("name")
                    .map(|n| ts_node_text(source_code, n).to_owned())?;
                let class_kinds = &["class_declaration", "class_expression"];
                let fully_qualified_name =
                    match enclosing_class_name(source_code, node, class_kinds) {
                        Some(cls) => format!("{cls}.{name}"),
                        None => name.clone(),
                    };
                return Some(EnclosingFunction {
                    name,
                    fully_qualified_name,
                });
            }
            // tree-sitter-javascript uses "function" for both anonymous and named function
            // expressions. "function_declaration" is used only for statement-level `function foo() {}`.
            "function" | "generator_function" => {
                if let Some(name_node) = node.child_by_field_name("name") {
                    // Named function expression: `const x = function myName() {}`
                    let name = ts_node_text(source_code, name_node).to_owned();
                    let fully_qualified_name = name.clone();
                    return Some(EnclosingFunction {
                        name,
                        fully_qualified_name,
                    });
                }
                // Anonymous function assigned to a variable: `const foo = function() {}`
                return enclosing_function_from_declarator_parent(source_code, node);
            }
            "arrow_function" => {
                // Arrow function assigned to a variable: `const foo = () => {}`
                return enclosing_function_from_declarator_parent(source_code, node);
            }
            _ => {}
        }
        node = node.parent()?;
    }
}

/// If `node`'s parent is a `variable_declarator`, returns an `EnclosingFunction` whose name and
/// `fullyQualifiedName` are taken from the declarator's variable name.
fn enclosing_function_from_declarator_parent(
    source_code: &str,
    node: tree_sitter::Node,
) -> Option<EnclosingFunction> {
    let parent = node.parent()?;
    if parent.kind() == "variable_declarator" {
        let name = ts_node_text(source_code, parent.child_by_field_name("name")?).to_owned();
        let fully_qualified_name = name.clone();
        Some(EnclosingFunction {
            name,
            fully_qualified_name,
        })
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::find_enclosing_function_with_tree;
    use crate::analysis::tree_sitter::get_tree;
    use crate::model::common::Language;
    use crate::model::violation::EnclosingFunction;

    fn find(source: &str, line: u32, col: u32) -> Option<EnclosingFunction> {
        let tree = get_tree(source, &Language::JavaScript).unwrap();
        find_enclosing_function_with_tree(source, &tree, line, col)
    }

    fn ef(name: &str, sig: &str) -> Option<EnclosingFunction> {
        Some(EnclosingFunction {
            name: name.to_string(),
            fully_qualified_name: sig.to_string(),
        })
    }

    #[test]
    fn inside_function_declaration() {
        let src = "\
function greet() {
    const x = 1;
}
";
        assert_eq!(find(src, 2, 5), ef("greet", "greet"));
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
        assert_eq!(find(src, 3, 9), ef("compute", "MyClass.compute"));
    }

    #[test]
    fn inside_arrow_function_assigned_to_const() {
        let src = "\
const handleEvent = () => {
    const x = 1;
};
";
        assert_eq!(find(src, 2, 5), ef("handleEvent", "handleEvent"));
    }

    #[test]
    fn inside_anonymous_function_assigned_to_var() {
        let src = "\
const process = function() {
    const x = 1;
};
";
        assert_eq!(find(src, 2, 5), ef("process", "process"));
    }

    #[test]
    fn named_function_expression_uses_explicit_name() {
        let src = "\
const x = function myFn() {
    const y = 1;
};
";
        assert_eq!(find(src, 2, 5), ef("myFn", "myFn"));
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
