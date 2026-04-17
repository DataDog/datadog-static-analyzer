// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::analysis::languages::ts_node_text;

/// Returns the name of the innermost method, constructor, or local function enclosing the given
/// source position, or `None` if the position is not inside any such construct.
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
            "method_declaration" | "constructor_declaration" | "local_function_statement" => {
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
        let tree = get_tree(source, &Language::Csharp).unwrap();
        find_enclosing_function(source, &tree, line, col)
    }

    #[test]
    fn inside_method() {
        let src = "\
class Foo {
    public void DoSomething() {
        var x = 1;
    }
}
";
        assert_eq!(find(src, 3, 9), Some("DoSomething".to_string()));
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
    fn inside_local_function() {
        let src = "\
class Foo {
    public void Outer() {
        void Inner() {
            var x = 1;
        }
    }
}
";
        assert_eq!(find(src, 4, 13), Some("Inner".to_string()));
    }

    #[test]
    fn class_field() {
        let src = "\
class Foo {
    int x = 1;
}
";
        assert_eq!(find(src, 2, 9), None);
    }
}
