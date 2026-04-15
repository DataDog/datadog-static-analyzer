// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::analysis::languages::ts_node_text;
use crate::analysis::tree_sitter::get_tree;
use crate::model::common::Language;

/// Returns the name of the innermost method or constructor enclosing the given source position,
/// or `None` if the position is not inside any method.
///
/// This function parses the source code from scratch.
/// If you already have a parsed tree, use [`find_enclosing_function_with_tree`].
pub fn find_enclosing_function(source_code: &str, line: u32, col: u32) -> Option<String> {
    get_tree(source_code, &Language::Java)
        .and_then(|tree| find_enclosing_function_with_tree(source_code, &tree, line, col))
}

/// Returns the name of the innermost method or constructor enclosing the given source position.
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
            "method_declaration" | "constructor_declaration" => {
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
        let tree = get_tree(source, &Language::Java).unwrap();
        find_enclosing_function_with_tree(source, &tree, line, col)
    }

    #[test]
    fn inside_method() {
        let src = "\
class Foo {
    public void doSomething() {
        int x = 1;
    }
}
";
        assert_eq!(find(src, 3, 9), Some("doSomething".to_string()));
    }

    #[test]
    fn inside_constructor() {
        let src = "\
class Foo {
    public Foo() {
        this.x = 0;
    }
}
";
        assert_eq!(find(src, 3, 9), Some("Foo".to_string()));
    }

    #[test]
    fn inside_method_with_throws() {
        let src = "\
class Foo {
    public void parse() throws IOException {
        int x = 1;
    }
}
";
        assert_eq!(find(src, 3, 9), Some("parse".to_string()));
    }

    #[test]
    fn top_level_field() {
        let src = "\
class Foo {
    int x = 1;
}
";
        assert_eq!(find(src, 2, 9), None);
    }
}
