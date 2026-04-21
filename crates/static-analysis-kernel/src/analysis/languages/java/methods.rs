// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use std::collections::HashMap;

use crate::analysis::languages::{enclosing_class_name, ts_node_text};
use crate::analysis::tree_sitter::get_tree;
use crate::model::common::Language;
use crate::model::violation::EnclosingFunction;

struct JavaFileContext {
    package: Option<String>,
    import_map: HashMap<String, String>,
}

impl JavaFileContext {
    fn new(source_code: &str, tree: &tree_sitter::Tree) -> Self {
        let root = tree.root_node();
        Self {
            package: find_package(source_code, root),
            import_map: build_import_map(source_code, root),
        }
    }
}

/// Returns the enclosing method or constructor for the given source position, or `None` if the
/// position is not inside any method.
///
/// This function parses the source code from scratch.
/// If you already have a parsed tree, use [`find_enclosing_function_with_tree`].
pub fn find_enclosing_function(
    source_code: &str,
    line: u32,
    col: u32,
) -> Option<EnclosingFunction> {
    get_tree(source_code, &Language::Java)
        .and_then(|tree| find_enclosing_function_with_tree(source_code, &tree, line, col))
}

/// Returns the enclosing method or constructor for the given source position.
/// See [`find_enclosing_function`] for documentation.
///
/// The `fully_qualified_name` follows the FQMN format:
///   `package.ClassName.methodName(ParamType1, ParamType2)`
///
/// Types are resolved to fully qualified names using the file's import declarations.
/// Types from `java.lang` (String, Integer, etc.) are always resolved. Types only
/// reachable via wildcard imports are returned as simple names.
///
pub fn find_enclosing_function_with_tree(
    source_code: &str,
    tree: &tree_sitter::Tree,
    line: u32,
    col: u32,
) -> Option<EnclosingFunction> {
    let ctx = JavaFileContext::new(source_code, tree);
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
                let name = node
                    .child_by_field_name("name")
                    .map(|n| ts_node_text(source_code, n).to_owned())?;
                let fully_qualified_name = build_fqn(source_code, &ctx, node, &name);
                return Some(EnclosingFunction {
                    name,
                    fully_qualified_name,
                });
            }
            _ => {}
        }
        node = node.parent()?;
    }
}

/// Builds the fully qualified method name (FQMN) in the format:
///   `package.ClassName.methodName(ParamType1, ParamType2)`
fn build_fqn(
    source_code: &str,
    ctx: &JavaFileContext,
    method_node: tree_sitter::Node,
    method_name: &str,
) -> String {
    let class_kinds = &[
        "class_declaration",
        "interface_declaration",
        "enum_declaration",
    ];
    let class_name = enclosing_class_name(source_code, method_node, class_kinds);

    let fqn_class = match (ctx.package.as_deref(), class_name) {
        (Some(pkg), Some(cls)) => format!("{pkg}.{cls}"),
        (None, Some(cls)) => cls.to_string(),
        (Some(pkg), None) => pkg.to_string(),
        (None, None) => String::new(),
    };

    let pkg = ctx.package.as_deref();

    let param_types = method_node
        .child_by_field_name("parameters")
        .map(|p| extract_param_types(source_code, p, &ctx.import_map, pkg))
        .unwrap_or_default();

    let params_str = param_types.join(", ");

    if fqn_class.is_empty() {
        format!("{method_name}({params_str})")
    } else {
        format!("{fqn_class}.{method_name}({params_str})")
    }
}

/// Returns the package name declared at the top of the compilation unit, if any.
fn find_package(source_code: &str, root: tree_sitter::Node) -> Option<String> {
    for i in 0..root.named_child_count() {
        let Some(child) = root.named_child(i) else {
            continue;
        };
        if child.kind() == "package_declaration" {
            for j in 0..child.named_child_count() {
                let Some(pkg_child) = child.named_child(j) else {
                    continue;
                };
                if matches!(pkg_child.kind(), "scoped_identifier" | "identifier") {
                    return Some(ts_node_text(source_code, pkg_child).to_owned());
                }
            }
        }
    }
    None
}

/// Builds a map of simple class name → fully qualified name from explicit (non-wildcard,
/// non-static) import declarations in the file.
fn build_import_map(source_code: &str, root: tree_sitter::Node) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for i in 0..root.named_child_count() {
        let Some(child) = root.named_child(i) else {
            continue;
        };
        if child.kind() != "import_declaration" {
            continue;
        }
        let text = ts_node_text(source_code, child);
        // Strip "import " prefix and ";" suffix, then trim whitespace
        let body = text
            .trim_start_matches("import")
            .trim()
            .trim_end_matches(';')
            .trim();
        // Skip static and wildcard imports — they can't be resolved without a classpath
        if body.starts_with("static ") || body.ends_with('*') {
            continue;
        }
        let simple_name = body.split('.').next_back().unwrap_or("").to_string();
        if !simple_name.is_empty() {
            map.insert(simple_name, body.to_string());
        }
    }
    map
}

/// Resolves a tree-sitter type node to a fully qualified type name where possible.
///
/// - Explicit imports: `MultipartFile` → `org.springframework.web.multipart.MultipartFile`
/// - java.lang types: `String` → `java.lang.String`
/// - Everything else: returned as the simple name from source
fn resolve_type(
    source_code: &str,
    type_node: tree_sitter::Node,
    import_map: &HashMap<String, String>,
    package: Option<&str>,
) -> String {
    match type_node.kind() {
        // Primitives and void — always use as-is
        "void_type" | "integral_type" | "floating_point_type" | "boolean_type" => {
            ts_node_text(source_code, type_node).to_owned()
        }
        // Simple class name reference
        "type_identifier" => {
            resolve_class_name(ts_node_text(source_code, type_node), import_map, package)
        }
        // Already fully qualified in source (rare)
        "scoped_type_identifier" => ts_node_text(source_code, type_node).to_owned(),
        // Generic type: List<String> → java.util.List<java.lang.String>
        "generic_type" => {
            let base = type_node
                .named_child(0)
                .map(|n| resolve_type(source_code, n, import_map, package))
                .unwrap_or_default();
            let type_args = type_node
                .named_child(1)
                .filter(|n| n.kind() == "type_arguments");
            match type_args {
                Some(args_node) => {
                    let args: Vec<String> = (0..args_node.named_child_count())
                        .filter_map(|i| args_node.named_child(i))
                        .map(|n| resolve_type(source_code, n, import_map, package))
                        .collect();
                    if args.is_empty() {
                        base
                    } else {
                        format!("{base}<{}>", args.join(", "))
                    }
                }
                None => base,
            }
        }
        // Array type: String[] — resolve element type and keep dimensions
        "array_type" => {
            let element = type_node
                .child_by_field_name("element")
                .map(|n| resolve_type(source_code, n, import_map, package))
                .unwrap_or_default();
            let dims = type_node
                .child_by_field_name("dimensions")
                .map(|n| ts_node_text(source_code, n))
                .unwrap_or("[]");
            format!("{element}{dims}")
        }
        // Annotated type: @NotNull String — strip annotation and resolve the underlying type
        "annotated_type" => {
            // The last named child is the actual type
            let count = type_node.named_child_count();
            type_node
                .named_child(count.saturating_sub(1))
                .map(|n| resolve_type(source_code, n, import_map, package))
                .unwrap_or_else(|| ts_node_text(source_code, type_node).to_owned())
        }
        // Wildcard (? extends Foo, ? super Bar) — keep as raw text
        "wildcard" => ts_node_text(source_code, type_node).to_owned(),
        _ => ts_node_text(source_code, type_node).to_owned(),
    }
}

/// Resolves a simple class name to its fully qualified form using explicit imports and
/// the well-known `java.lang` package that is always implicitly available.
fn resolve_class_name(
    name: &str,
    import_map: &HashMap<String, String>,
    _package: Option<&str>,
) -> String {
    if let Some(fqn) = import_map.get(name) {
        return fqn.clone();
    }
    if JAVA_LANG_TYPES.contains(&name) {
        return format!("java.lang.{name}");
    }
    name.to_owned()
}

/// Extracts the ordered list of parameter types from a `formal_parameters` node.
/// Annotations and variable names are excluded; only the type is kept.
fn extract_param_types(
    source_code: &str,
    params_node: tree_sitter::Node,
    import_map: &HashMap<String, String>,
    package: Option<&str>,
) -> Vec<String> {
    let mut types = vec![];
    for i in 0..params_node.named_child_count() {
        let Some(child) = params_node.named_child(i) else {
            continue;
        };
        match child.kind() {
            "formal_parameter" => {
                if let Some(type_node) = child.child_by_field_name("type") {
                    types.push(resolve_type(source_code, type_node, import_map, package));
                }
            }
            "spread_parameter" => {
                // Varargs: `Type... name` — type field exists on spread_parameter too
                if let Some(type_node) = child.child_by_field_name("type") {
                    let t = resolve_type(source_code, type_node, import_map, package);
                    types.push(format!("{t}..."));
                }
            }
            _ => {}
        }
    }
    types
}

// Types always in scope from java.lang.* (implicit import in every Java file)
const JAVA_LANG_TYPES: &[&str] = &[
    "AutoCloseable",
    "Boolean",
    "Byte",
    "CharSequence",
    "Character",
    "Class",
    "ClassLoader",
    "Cloneable",
    "Comparable",
    "Double",
    "Enum",
    "Error",
    "Exception",
    "Float",
    "Integer",
    "Iterable",
    "Long",
    "Math",
    "Number",
    "Object",
    "Process",
    "Runnable",
    "Runtime",
    "RuntimeException",
    "Short",
    "String",
    "StringBuffer",
    "StringBuilder",
    "System",
    "Thread",
    "Throwable",
    "Void",
];

#[cfg(test)]
mod tests {
    use super::find_enclosing_function_with_tree;
    use crate::analysis::tree_sitter::get_tree;
    use crate::model::common::Language;
    use crate::model::violation::EnclosingFunction;

    fn find(source: &str, line: u32, col: u32) -> Option<EnclosingFunction> {
        let tree = get_tree(source, &Language::Java).unwrap();
        find_enclosing_function_with_tree(source, &tree, line, col)
    }

    fn ef(name: &str, sig: &str) -> Option<EnclosingFunction> {
        Some(EnclosingFunction {
            name: name.to_string(),
            fully_qualified_name: sig.to_string(),
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
        assert_eq!(find(src, 3, 9), ef("doSomething", "Foo.doSomething()"));
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
    fn with_package() {
        let src = "\
package com.example;
class Foo {
    public void doSomething() {
        int x = 1;
    }
}
";
        assert_eq!(
            find(src, 4, 9),
            ef("doSomething", "com.example.Foo.doSomething()")
        );
    }

    #[test]
    fn java_lang_type_resolved() {
        // String is in java.lang and always resolved without an explicit import
        let src = "\
class Foo {
    public void handle(String s) {
        int x = 1;
    }
}
";
        assert_eq!(
            find(src, 3, 9),
            ef("handle", "Foo.handle(java.lang.String)")
        );
    }

    #[test]
    fn explicit_import_resolved() {
        let src = "\
import org.springframework.web.multipart.MultipartFile;
import org.springframework.ui.Model;
class Foo {
    public String process(MultipartFile file, Model model) {
        return \"ok\";
    }
}
";
        assert_eq!(
            find(src, 4, 9),
            ef(
                "process",
                "Foo.process(org.springframework.web.multipart.MultipartFile, org.springframework.ui.Model)"
            )
        );
    }

    #[test]
    fn full_fqn_with_package_and_imports() {
        let src = "\
package org.hdivsamples.controllers;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.ui.Model;
class DashboardController {
    public String processSimple(MultipartFile file, Model model) {
        return \"ok\";
    }
}
";
        assert_eq!(
            find(src, 5, 9),
            ef(
                "processSimple",
                "org.hdivsamples.controllers.DashboardController.processSimple(org.springframework.web.multipart.MultipartFile, org.springframework.ui.Model)"
            )
        );
    }

    #[test]
    fn annotations_not_in_fqn() {
        // Method and parameter annotations are excluded from the FQN
        let src = "\
class Foo {
    @Override
    public void doSomething() {
        int x = 1;
    }
}
";
        assert_eq!(find(src, 4, 9), ef("doSomething", "Foo.doSomething()"));
    }

    #[test]
    fn throws_not_in_fqn() {
        // throws clause is not part of the standard Java FQN
        let src = "\
class Foo {
    public void parse() throws IOException {
        int x = 1;
    }
}
";
        assert_eq!(find(src, 3, 9), ef("parse", "Foo.parse()"));
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
