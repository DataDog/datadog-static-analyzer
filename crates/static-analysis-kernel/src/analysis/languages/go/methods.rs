// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::analysis::languages::ts_node_text;
use crate::analysis::tree_sitter::get_tree;
use crate::model::common::Language;

/// Returns the name of the innermost function or method enclosing the given source position,
/// or `None` if the position is not inside any function.
///
/// This function parses the source code from scratch.
/// If you already have a parsed tree, use [`find_enclosing_function_with_tree`].
pub fn find_enclosing_function(source_code: &str, line: u32, col: u32) -> Option<String> {
    get_tree(source_code, &Language::Go)
        .and_then(|tree| find_enclosing_function_with_tree(source_code, &tree, line, col))
}

/// Returns the name of the innermost function or method enclosing the given source position.
/// See [`find_enclosing_function`] for documentation.
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
            "function_declaration" | "method_declaration" => {
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
    use super::{find_enclosing_function, find_enclosing_function_with_tree};
    use crate::analysis::tree_sitter::get_tree;
    use crate::model::common::Language;

    fn find(source: &str, line: u32, col: u32) -> Option<String> {
        let tree = get_tree(source, &Language::Go).unwrap();
        find_enclosing_function_with_tree(source, &tree, line, col)
    }

    #[test]
    fn inside_function() {
        let src = "\
package main

func greet() {
    x := 1
}
";
        assert_eq!(find(src, 4, 5), Some("greet".to_string()));
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
        assert_eq!(find(src, 6, 5), Some("Handle".to_string()));
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
