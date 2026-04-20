// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::analysis::languages::{enclosing_class_name, ts_node_text};
use crate::analysis::tree_sitter::get_tree;
use crate::model::common::Language;
use crate::model::violation::EnclosingFunction;

/// Returns the enclosing method, constructor, or local function for the given source position,
/// or `None` if the position is not inside any such construct.
///
/// This function parses the source code from scratch.
/// If you already have a parsed tree, use [`find_enclosing_function_with_tree`].
pub fn find_enclosing_function(source_code: &str, line: u32, col: u32) -> Option<EnclosingFunction> {
    get_tree(source_code, &Language::Csharp)
        .and_then(|tree| find_enclosing_function_with_tree(source_code, &tree, line, col))
}

/// Returns the enclosing method, constructor, or local function for the given source position.
/// See [`find_enclosing_function`] for documentation.
///
/// The `fullyQualifiedName` follows the Roslyn / XML documentation ID convention:
///   `Namespace.ClassName.MethodName(ParamType1, ParamType2)`
///
/// Access modifiers, attributes (`[HttpGet]`), and the return type are excluded.
/// Parameter types are included as simple names (not namespace-resolved), consistent
/// with how Roslyn presents method signatures in quick-info and SARIF output.
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
            "method_declaration" | "constructor_declaration" | "local_function_statement" => {
                let name = node
                    .child_by_field_name("name")
                    .map(|n| ts_node_text(source_code, n).to_owned())?;

                let class_kinds = &[
                    "class_declaration",
                    "interface_declaration",
                    "struct_declaration",
                    "record_declaration",
                ];
                let namespace = find_namespace(source_code, node);
                let class_name = enclosing_class_name(source_code, node, class_kinds);

                let fqn_prefix = match (namespace.as_deref(), class_name) {
                    (Some(ns), Some(cls)) => format!("{ns}.{cls}"),
                    (None, Some(cls)) => cls.to_string(),
                    (Some(ns), None) => ns.to_string(),
                    (None, None) => String::new(),
                };

                let param_types = node
                    .child_by_field_name("parameters")
                    .map(|p| extract_param_types(source_code, p))
                    .unwrap_or_default();

                let params_str = param_types.join(", ");
                let fully_qualified_name = if fqn_prefix.is_empty() {
                    format!("{name}({params_str})")
                } else {
                    format!("{fqn_prefix}.{name}({params_str})")
                };

                return Some(EnclosingFunction { name, fully_qualified_name });
            }
            _ => {}
        }
        node = node.parent()?;
    }
}

/// Walks up from `node` collecting names from every enclosing `namespace_declaration` or
/// `file_scoped_namespace_declaration`, then joins them outermost-first with `.`.
///
/// Handles both nested namespace blocks and the C# 10 file-scoped `namespace Foo.Bar;` form.
fn find_namespace(source_code: &str, mut node: tree_sitter::Node) -> Option<String> {
    let mut parts: Vec<String> = vec![];
    loop {
        node = match node.parent() {
            Some(p) => p,
            None => break,
        };
        if matches!(node.kind(), "namespace_declaration" | "file_scoped_namespace_declaration") {
            if let Some(name_node) = node.child_by_field_name("name") {
                parts.push(ts_node_text(source_code, name_node).to_owned());
            }
        }
    }
    if parts.is_empty() {
        None
    } else {
        parts.reverse(); // outermost namespace first
        Some(parts.join("."))
    }
}

/// Extracts the ordered list of parameter types from a `parameter_list` node.
/// Attributes (`[FromBody]`), modifiers (`ref`, `out`, `params`), and parameter names
/// are excluded — only the type name is kept.
fn extract_param_types(source_code: &str, params_node: tree_sitter::Node) -> Vec<String> {
    let mut types = vec![];
    for i in 0..params_node.named_child_count() {
        let Some(child) = params_node.named_child(i) else { continue };
        if child.kind() == "parameter" {
            if let Some(type_node) = child.child_by_field_name("type") {
                types.push(ts_node_text(source_code, type_node).to_owned());
            }
        }
    }
    types
}

#[cfg(test)]
mod tests {
    use super::{find_enclosing_function, find_enclosing_function_with_tree};
    use crate::analysis::tree_sitter::get_tree;
    use crate::model::common::Language;
    use crate::model::violation::EnclosingFunction;

    fn find(source: &str, line: u32, col: u32) -> Option<EnclosingFunction> {
        let tree = get_tree(source, &Language::Csharp).unwrap();
        find_enclosing_function_with_tree(source, &tree, line, col)
    }

    fn ef(name: &str, sig: &str) -> Option<EnclosingFunction> {
        Some(EnclosingFunction { name: name.to_string(), fully_qualified_name: sig.to_string() })
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
        assert_eq!(find(src, 3, 9), ef("DoSomething", "Foo.DoSomething()"));
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
        assert_eq!(find(src, 3, 9), ef("Foo", "Foo.Foo()"));
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
        assert_eq!(find(src, 4, 13), ef("Inner", "Foo.Inner()"));
    }

    #[test]
    fn with_namespace() {
        let src = "\
namespace MyApp.Controllers {
    class Foo {
        public void DoSomething() {
            var x = 1;
        }
    }
}
";
        assert_eq!(find(src, 4, 13), ef("DoSomething", "MyApp.Controllers.Foo.DoSomething()"));
    }

    #[test]
    fn with_parameters() {
        let src = "\
namespace MyApp {
    class Foo {
        public void Handle(string req, int count) {
            var x = 1;
        }
    }
}
";
        assert_eq!(find(src, 4, 13), ef("Handle", "MyApp.Foo.Handle(string, int)"));
    }

    #[test]
    fn skips_attribute() {
        let src = "\
class Foo {
    [HttpGet]
    public void Handle() {
        var x = 1;
    }
}
";
        assert_eq!(find(src, 4, 9), ef("Handle", "Foo.Handle()"));
    }

    #[test]
    fn skips_complex_attribute() {
        let src = "\
class Foo {
    [Route(\"/path\")]
    [HttpGet]
    public void Handle(string req) {
        var x = 1;
    }
}
";
        assert_eq!(find(src, 5, 9), ef("Handle", "Foo.Handle(string)"));
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
