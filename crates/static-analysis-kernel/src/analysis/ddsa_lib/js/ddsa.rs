// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-2025 Datadog, Inc.

// (NB: There is no need for any Rust business logic here, as `ddsa.js` is purely the user-facing JavaScript API)

const CLASS_NAME: &str = "DDSA";

#[cfg(test)]
mod tests {
    use super::CLASS_NAME;
    use crate::analysis::ddsa_lib::test_utils::{
        cfg_test_v8, js_class_eq, js_instance_eq, shorthand_execute_rule,
    };
    use crate::analysis::tree_sitter::get_tree_sitter_language;
    use crate::model::common::Language::Python;

    #[test]
    fn js_properties_canary() {
        let expected = &[
            // Methods
            "getChildren",
            "getParentWithCondition",
            "getChildWithCondition",
            "getParent",
            "getTaintSinks",
            "getTaintSources",
        ];
        assert!(js_instance_eq(CLASS_NAME, expected));
        let expected = &[];
        assert!(js_class_eq(CLASS_NAME, expected));
    }

    /// `op_ts_node_named_children` returns only named children, and requests nodes lazily from the bridge.
    #[test]
    fn op_ts_node_named_children() {
        compat_helper_op_ts_node_named_children("ddsa.getChildren(node)")
    }

    #[test]
    fn test_get_child_with_condition() {
        let mut rt = cfg_test_v8().new_runtime();
        let text = "print(foo)";
        let ts_query = "(module)@module";
        let rule_code = r#"
function isIdentifier(n) {{
    if (n.cstType === "identifier") {{
        return true;
    }}
    return false;
}}

function visit(query, filename, code) {{
  const n = query.captures.module;
  const c = ddsa.getChildWithCondition(n, isIdentifier);
  console.log(c.text);
}}
"#;

        // Then execute the rule that fetches the children of the node.
        let res =
            shorthand_execute_rule(&mut rt, Python, ts_query, &rule_code, text, None).unwrap();
        assert_eq!(res.console_lines[0], "print");
    }

    #[test]
    fn test_get_parent_with_condition() {
        let mut rt = cfg_test_v8().new_runtime();
        let text = "print(\"foo\")";
        let ts_query = "(string_content)@sc";
        let rule_code = r#"
function isModule(n) {{
    if (n.cstType === "module") {{
        return true;
    }}
    return false;
}}

function visit(query, filename, code) {{
  const n = query.captures.sc;
  const c = ddsa.getParentWithCondition(n, getModule);
  console.log(c);
  console.log(c.text);
}}
"#;

        // Then execute the rule that fetches the children of the node.
        let res =
            shorthand_execute_rule(&mut rt, Python, ts_query, &rule_code, text, None).unwrap();
        assert_eq!(res.console_lines[0], "print(\"#foo\")");
    }

    /// Stella syntax can get named children
    #[test]
    fn op_ts_node_named_children_stella_compat() {
        compat_helper_op_ts_node_named_children("node.children")
    }

    /// NOTE: This is temporary scaffolding used during the transition to `ddsa_lib`.
    fn compat_helper_op_ts_node_named_children(get_children: &str) {
        use crate::model::common::Language::JavaScript;
        let mut rt = cfg_test_v8().new_runtime();
        let text = "function echo(a, b, c) {}";
        let ts_query = r#"
((function_declaration
    (formal_parameters) @paramList))
"#;
        let noop = r#"
function visit(captures) { }
"#;
        let get_children = format!(
            r#"
function visit(captures) {{
    const node = captures.get("paramList");
    const children = {get_children};
    console.log(children.map((c) => c.text));
}}
"#,
        );
        // First run a no-op rule to assert that only 1 (captured) node is sent to the bridge.
        shorthand_execute_rule(&mut rt, JavaScript, ts_query, noop, text, None).unwrap();
        assert_eq!(rt.bridge_ts_node().borrow().len(), 1);
        // Then execute the rule that fetches the children of the node.
        let res = shorthand_execute_rule(&mut rt, JavaScript, ts_query, &get_children, text, None)
            .unwrap();
        // We should've newly pushed the captured node's 3 children to the bridge.
        assert_eq!(rt.bridge_ts_node().borrow().len(), 4);
        assert_eq!(res.console_lines[0], r#"["a","b","c"]"#);

        // Check a node with no children.
        let text = "function echo() {}";
        let res = shorthand_execute_rule(&mut rt, JavaScript, ts_query, &get_children, text, None)
            .unwrap();
        assert_eq!(res.console_lines[0], "[]");
    }

    /// Tests that a child node can have a `fieldName`, but that not all child nodes do.
    #[test]
    fn child_node_with_field() {
        use crate::model::common::Language::JavaScript;
        // (Assertion included to alert if upstream tree-sitter grammar unexpectedly alters metadata)
        let ts_lang = get_tree_sitter_language(&JavaScript);
        assert_eq!(ts_lang.field_name_for_id(26).unwrap(), "name");

        let mut rt = cfg_test_v8().new_runtime();
        let text = "function echo(a, b) { /* ... */ }";
        let tsq_with_fields = r#"
    (function_declaration) @cap_name
    "#;
        let tsq_no_fields = r#"
    ((function_declaration
        (formal_parameters) @cap_name))
    "#;
        let code = r#"
    function visit(captures) {
        const node = captures.get("cap_name");
        const firstChild = ddsa.getChildren(node)[0];
        console.log(firstChild._fieldId, firstChild.fieldName);
    }
    "#;
        // Some children should have a fieldName
        let res =
            shorthand_execute_rule(&mut rt, JavaScript, tsq_with_fields, code, text, None).unwrap();
        assert_eq!(res.console_lines[0], "26 name");

        // Others do not
        let res =
            shorthand_execute_rule(&mut rt, JavaScript, tsq_no_fields, code, text, None).unwrap();
        assert_eq!(res.console_lines[0], "undefined undefined");
    }

    /// `op_ts_node_parent` returns the node's parent. Calling the op on the tree's root node returns `undefined`.
    #[test]
    fn op_ts_node_parent() {
        use crate::model::common::Language::JavaScript;
        let mut rt = cfg_test_v8().new_runtime();
        let text = "function echo() { /* code */ }";
        let ts_query = r#"
(statement_block) @stmt
"#;
        let get_parent = r#"
function visit(captures) {
    const node = captures.get("stmt");
    const node1 = node;
    const node2 = ddsa.getParent(node1);
    const node3 = ddsa.getParent(node2); // (This is the root)
    const node4 = ddsa.getParent(node3);
    console.log(node1.cstType, node2.cstType, node3.cstType, node4);
}
"#;
        // Then execute the rule that fetches the parent of the node.
        let res =
            shorthand_execute_rule(&mut rt, JavaScript, ts_query, get_parent, text, None).unwrap();
        // Checking the node's cstType and its parent's cstType is a simple verification that this works.
        let expected_output = "statement_block function_declaration program undefined";
        assert_eq!(res.console_lines[0], expected_output);
    }

    /// `op_ts_node_parent` only serializes the immediate parent, not the entire ancestor chain.
    /// (We do this test because we know that in order to get a node's parent, in Rust, we are caching the
    /// entire root-to-node path, and we want to ensure we aren't pushing it all to JavaScript at once).
    #[test]
    fn op_ts_node_parent_lazy_serialization() {
        use crate::model::common::Language::JavaScript;
        let mut rt = cfg_test_v8().new_runtime();
        let text = "function echo() { /* code */ }";
        let ts_query = r#"
(statement_block) @stmt
"#;
        let get_parent = r#"
function visit(captures) {
    console.log(globalThis.__RUST_BRIDGE__ts_node.size);
    const node = captures.get("stmt");
    // Captured node and its parent
    console.log(node.cstType, ddsa.getParent(node).cstType);
    console.log(globalThis.__RUST_BRIDGE__ts_node.size);
    // Captured node's grandparent
    console.log(ddsa.getParent(ddsa.getParent(node)).cstType);
    console.log(globalThis.__RUST_BRIDGE__ts_node.size);
}
"#;
        // Execute a rule that fetches the parent of the node. We use `console.log` within the
        // JavaScript to inspect the bridge state and `assert!` on it within the Rust unit test.
        let res =
            shorthand_execute_rule(&mut rt, JavaScript, ts_query, get_parent, text, None).unwrap();
        // Initially, only 1 node should have been serialized.
        assert_eq!(res.console_lines[0], "1");
        // The parent should have been properly retrieved.
        assert_eq!(res.console_lines[1], "statement_block function_declaration");
        // Only one extra node should have been serialized
        assert_eq!(res.console_lines[2], "2");
        // For test integrity, prove that this is truly lazy by confirming that the length of
        // the `@stmt` node's ancestor chain is greater than 1.
        assert_eq!(res.console_lines[3], "program", "test invariant broken");
        // Only now should the grandparent have been serialized.
        assert_eq!(res.console_lines[4], "3", "test invariant broken");
    }
}
