// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::analysis::languages::ts_node_text;

/// Returns the name of the innermost function or method enclosing the given source position,
/// or `None` if the position is not inside any function.
pub fn find_enclosing_function(
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
            "function_definition" | "async_function_definition" => {
                return node
                    .child_by_field_name("name")
                    .map(|n| ts_node_text(source_code, n).to_owned());
            }
            _ => {}
        }
        node = node.parent()?;
    }
}

#[cfg(test)]
mod tests {
    use super::find_enclosing_function;
    use crate::analysis::tree_sitter::get_tree;
    use crate::model::common::Language;

    fn find(source: &str, line: u32, col: u32) -> Option<String> {
        let tree = get_tree(source, &Language::Python).unwrap();
        find_enclosing_function(source, &tree, line, col)
    }

    #[test]
    fn inside_function() {
        let src = "\
def my_func():
    x = 1
";
        assert_eq!(find(src, 2, 5), Some("my_func".to_string()));
    }

    #[test]
    fn inside_async_function() {
        let src = "\
async def handle_request():
    pass
";
        assert_eq!(find(src, 2, 5), Some("handle_request".to_string()));
    }

    #[test]
    fn inside_method() {
        let src = "\
class MyClass:
    def compute(self):
        return 42
";
        assert_eq!(find(src, 3, 9), Some("compute".to_string()));
    }

    #[test]
    fn top_level_code() {
        let src = "x = 1\n";
        assert_eq!(find(src, 1, 1), None);
    }

    #[test]
    fn nested_function_returns_inner() {
        let src = "\
def outer():
    def inner():
        pass
";
        assert_eq!(find(src, 3, 9), Some("inner".to_string()));
    }
}
