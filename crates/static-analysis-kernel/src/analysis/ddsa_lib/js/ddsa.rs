// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

// (NB: There is no need for any Rust business logic here, as `ddsa.js` is purely the user-facing JavaScript API)

const CLASS_NAME: &str = "DDSA";

#[cfg(test)]
mod tests {
    use super::CLASS_NAME;
    use crate::analysis::ddsa_lib::test_utils::{
        js_class_eq, js_instance_eq, shorthand_execute_rule,
    };
    use crate::analysis::ddsa_lib::JsRuntime;
    use crate::analysis::tree_sitter::get_tree_sitter_language;

    #[test]
    fn js_properties_canary() {
        let expected = &[
            // Methods
            "getChildren",
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

    /// Stella syntax can get named children
    #[test]
    fn op_ts_node_named_children_stella_compat() {
        compat_helper_op_ts_node_named_children("node.children")
    }

    /// NOTE: This is temporary scaffolding used during the transition to `ddsa_lib`.
    fn compat_helper_op_ts_node_named_children(get_children: &str) {
        use crate::model::common::Language::JavaScript;
        let mut rt = JsRuntime::try_new().unwrap();
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

        let mut rt = JsRuntime::try_new().unwrap();
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
}
