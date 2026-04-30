// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::analysis::languages::ts_node_text;
use crate::analysis::tree_sitter::get_tree;
use crate::model::common::Language;
use crate::model::violation::EnclosingFunction;

/// Returns the enclosing method or constructor for the given source position, or `None` if the
/// position is not inside any method.
///
/// This function parses the source code from scratch.
/// If you already have a parsed tree, use [`find_enclosing_function_with_tree`].
pub fn find_enclosing_function(
    source_code: &str,
    start_line: u32,
    start_col: u32,
    end_line: u32,
    end_col: u32,
) -> Option<EnclosingFunction> {
    get_tree(source_code, &Language::Java).and_then(|tree| {
        find_enclosing_function_with_tree(
            source_code,
            &tree,
            start_line,
            start_col,
            end_line,
            end_col,
        )
    })
}

/// Returns the enclosing method or constructor for the given source position.
pub fn find_enclosing_function_with_tree(
    source_code: &str,
    tree: &tree_sitter::Tree,
    start_line: u32,
    start_col: u32,
    end_line: u32,
    end_col: u32,
) -> Option<EnclosingFunction> {
    let start = tree_sitter::Point {
        row: start_line.saturating_sub(1) as usize,
        column: start_col.saturating_sub(1) as usize,
    };
    let end = tree_sitter::Point {
        row: end_line.saturating_sub(1) as usize,
        column: end_col.saturating_sub(1) as usize,
    };
    let mut node = tree
        .root_node()
        .named_descendant_for_point_range(start, end)?;
    loop {
        match node.kind() {
            "method_declaration" | "constructor_declaration" => {
                let name = node
                    .child_by_field_name("name")
                    .map(|n| ts_node_text(source_code, n).to_owned())?;
                return Some(EnclosingFunction { name });
            }
            _ => {}
        }
        node = node.parent()?;
    }
}

#[cfg(test)]
mod tests {
    use super::find_enclosing_function_with_tree;
    use crate::analysis::tree_sitter::get_tree;
    use crate::model::common::Language;
    use crate::model::violation::EnclosingFunction;

    fn find(source: &str, line: u32, col: u32) -> Option<EnclosingFunction> {
        let tree = get_tree(source, &Language::Java).unwrap();
        find_enclosing_function_with_tree(source, &tree, line, col, line, col)
    }

    fn ef(name: &str) -> Option<EnclosingFunction> {
        Some(EnclosingFunction {
            name: name.to_string(),
        })
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
        assert_eq!(find(src, 3, 9), ef("doSomething"));
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
        assert_eq!(find(src, 3, 9), ef("Foo"));
    }

    #[test]
    fn with_package() {
        let src = "\
package com.example;
class Foo {
    public void doSomething() {
        int x = 1;
    }
}
";
        assert_eq!(find(src, 4, 9), ef("doSomething"));
    }

    #[test]
    fn with_params() {
        let src = "\
class Foo {
    public void handle(String s, int n) {
        int x = 1;
    }
}
";
        assert_eq!(find(src, 3, 9), ef("handle"));
    }

    #[test]
    fn annotations_ignored() {
        let src = "\
class Foo {
    @Override
    public void doSomething() {
        int x = 1;
    }
}
";
        assert_eq!(find(src, 4, 9), ef("doSomething"));
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

    // Lambdas are not named, so we report the nearest enclosing named method instead.
    // Naming individual lambdas is not implemented.
    #[test]
    fn inside_lambda_reports_enclosing_method() {
        let src = "\
class Foo {
    public void doWork() {
        Runnable r = () -> {
            int x = 1;
        };
    }
}
";
        assert_eq!(find(src, 4, 13), ef("doWork"));
    }
}
