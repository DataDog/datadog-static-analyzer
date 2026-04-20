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
pub fn find_enclosing_function(source_code: &str, line: u32, col: u32) -> Option<EnclosingFunction> {
    get_tree(source_code, &Language::TypeScript)
        .and_then(|tree| find_enclosing_function_with_tree(source_code, &tree, line, col))
}

/// Returns the enclosing function or method for the given source position.
/// See [`find_enclosing_function`] for documentation.
///
/// The TypeScript grammar shares all JavaScript function node types and additionally introduces
/// `method_signature` (interface members). The `fullyQualifiedName` follows the same convention
/// as JavaScript (V8/tooling standard): no type annotations, no modifiers.
///
///   - Top-level function: `functionName`
///   - Class method / interface method: `ClassName.methodName`
///   - Arrow/anonymous function assigned to a variable: `variableName`
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
                return Some(EnclosingFunction { name, fully_qualified_name });
            }
            "method_definition" | "method_signature" => {
                let name = node
                    .child_by_field_name("name")
                    .map(|n| ts_node_text(source_code, n).to_owned())?;
                let class_kinds = &["class_declaration", "class_expression"];
                let fully_qualified_name =
                    match enclosing_class_name(source_code, node, class_kinds) {
                        Some(cls) => format!("{cls}.{name}"),
                        None => name.clone(),
                    };
                return Some(EnclosingFunction { name, fully_qualified_name });
            }
            // tree-sitter-typescript (TSX) uses "function" for both anonymous and named function
            // expressions, same as tree-sitter-javascript.
            "function" | "generator_function" => {
                if let Some(name_node) = node.child_by_field_name("name") {
                    let name = ts_node_text(source_code, name_node).to_owned();
                    let fully_qualified_name = name.clone();
                    return Some(EnclosingFunction { name, fully_qualified_name });
                }
                return enclosing_function_from_declarator_parent(source_code, node);
            }
            "arrow_function" => {
                return enclosing_function_from_declarator_parent(source_code, node);
            }
            _ => {}
        }
        node = node.parent()?;
    }
}

fn enclosing_function_from_declarator_parent(
    source_code: &str,
    node: tree_sitter::Node,
) -> Option<EnclosingFunction> {
    let parent = node.parent()?;
    if parent.kind() == "variable_declarator" {
        let name = ts_node_text(source_code, parent.child_by_field_name("name")?).to_owned();
        let fully_qualified_name = name.clone();
        Some(EnclosingFunction { name, fully_qualified_name })
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::{find_enclosing_function, find_enclosing_function_with_tree};
    use crate::analysis::tree_sitter::get_tree;
    use crate::model::common::Language;
    use crate::model::violation::EnclosingFunction;

    fn find(source: &str, line: u32, col: u32) -> Option<EnclosingFunction> {
        let tree = get_tree(source, &Language::TypeScript).unwrap();
        find_enclosing_function_with_tree(source, &tree, line, col)
    }

    fn ef(name: &str, sig: &str) -> Option<EnclosingFunction> {
        Some(EnclosingFunction { name: name.to_string(), fully_qualified_name: sig.to_string() })
    }

    #[test]
    fn inside_function_declaration() {
        let src = "\
function greet(): void {
    const x = 1;
}
";
        assert_eq!(find(src, 2, 5), ef("greet", "greet"));
    }

    #[test]
    fn inside_class_method() {
        let src = "\
class MyService {
    compute(): number {
        return 42;
    }
}
";
        assert_eq!(find(src, 3, 9), ef("compute", "MyService.compute"));
    }

    #[test]
    fn inside_arrow_function() {
        let src = "\
const handler = (req: Request): void => {
    const x = 1;
};
";
        assert_eq!(find(src, 2, 5), ef("handler", "handler"));
    }

    #[test]
    fn top_level_code() {
        let src = "const x: number = 1;\n";
        assert_eq!(find(src, 1, 1), None);
    }
}
