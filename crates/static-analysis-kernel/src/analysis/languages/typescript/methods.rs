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
    get_tree(source_code, &Language::TypeScript)
        .and_then(|tree| find_enclosing_function_with_tree(source_code, &tree, line, col))
}

/// Returns the name of the innermost function or method enclosing the given source position.
/// See [`find_enclosing_function`] for documentation.
///
/// The TypeScript grammar (tree-sitter-typescript / TSX) shares all JavaScript function node
/// types and additionally introduces:
/// - `public_field_definition` (class fields with arrow initializers, not a function body)
///
/// Arrow functions and anonymous functions assigned to variables are handled the same way as in
/// JavaScript: the name is inferred from the surrounding `variable_declarator`.
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
            "method_definition" | "method_signature" => {
                return node
                    .child_by_field_name("name")
                    .map(|n| ts_node_text(source_code, n).to_owned());
            }
            // tree-sitter-typescript (TSX) uses "function" for both anonymous and named function
            // expressions, same as tree-sitter-javascript.
            "function" | "generator_function" => {
                if let Some(name_node) = node.child_by_field_name("name") {
                    return Some(ts_node_text(source_code, name_node).to_owned());
                }
                return name_from_variable_declarator_parent(source_code, node);
            }
            "arrow_function" => {
                return name_from_variable_declarator_parent(source_code, node);
            }
            _ => {}
        }
        node = node.parent()?;
    }
}

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
        let tree = get_tree(source, &Language::TypeScript).unwrap();
        find_enclosing_function_with_tree(source, &tree, line, col)
    }

    #[test]
    fn inside_function_declaration() {
        let src = "\
function greet(): void {
    const x = 1;
}
";
        assert_eq!(find(src, 2, 5), Some("greet".to_string()));
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
        assert_eq!(find(src, 3, 9), Some("compute".to_string()));
    }

    #[test]
    fn inside_arrow_function() {
        let src = "\
const handler = (req: Request): void => {
    const x = 1;
};
";
        assert_eq!(find(src, 2, 5), Some("handler".to_string()));
    }

    #[test]
    fn top_level_code() {
        let src = "const x: number = 1;\n";
        assert_eq!(find(src, 1, 1), None);
    }
}
