// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

/// A non-exhaustive list of binary expression operators.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) enum BinOp {
    Ignored = 0,
    Add = 1,
}

/// Returns a [`BinOp`] from a binary expression (or `None` if the provided node isn't a `binary_expression`).
pub(crate) fn get_binary_expression_operator(node: tree_sitter::Node) -> Option<BinOp> {
    if node.kind() != "binary_expression" {
        return None;
    }
    let mut operator: Option<BinOp> = None;
    for i in 0..node.child_count() {
        let child = node.child(i).expect("i should be less than child_count");
        operator = match child.kind() {
            "+" => Some(BinOp::Add),
            _ => None,
        };
        if operator.is_some() {
            break;
        }
    }
    Some(operator.unwrap_or(BinOp::Ignored))
}

#[cfg(test)]
mod tests {
    use super::{get_binary_expression_operator, BinOp};
    use crate::analysis::ddsa_lib::common::compile_script;
    use crate::analysis::ddsa_lib::js::flow::graph::{cst_dot_digraph, cst_v8_digraph, Digraph};
    use crate::analysis::ddsa_lib::test_utils::{cfg_test_runtime, try_execute, TsTree};
    use crate::analysis::ddsa_lib::JsRuntime;
    use crate::analysis::tree_sitter::get_tree;
    use crate::model::common::Language;
    use deno_core::v8;
    use std::sync::Arc;

    /// The name of the class that implements the graph creation logic.
    pub(crate) const CLASS_NAME: &str = "MethodFlow";

    /// Returns the first child with the given field name. Panics if it doesn't exist.
    fn field_child<'a>(node: tree_sitter::Node<'a>, name: &str) -> tree_sitter::Node<'a> {
        node.child_by_field_name(name).unwrap()
    }

    /// Converts a `source_text` to a `tree_sitter::Tree`, serializes all `tree_sitter::Node`s to v8,
    /// and injects helper functions into the JavaScript context.
    #[rustfmt::skip]
    pub(crate) fn setup(source_text: &str) -> (JsRuntime, TsTree) {
        let mut rt = JsRuntime::try_new().unwrap();
        let tree = TsTree::new(source_text, Language::Java);
        let source_text = Arc::<str>::from(source_text);
        let filename = Arc::<str>::from("test_doesnt_use_filename");
        rt.bridge_context().borrow_mut().set_root_context(&mut rt.v8_handle_scope(), &tree.tree(), &source_text, &filename);
        let tsn_bridge = rt.bridge_ts_node();
        let mut tsn_bridge = tsn_bridge.borrow_mut();
        for node in tree.find_named_nodes(None, None) {
            tsn_bridge.insert(&mut rt.v8_handle_scope(), node);
        }

        (rt, tree)
    }

    /// A Java test case.
    pub(crate) struct Java {
        /// The expected digraph.
        pub expected: Digraph,
        /// The complete digraph generated from source code.
        pub full: Digraph,
    }

    impl Java {
        /// Creates a new test case.
        ///
        /// # Params
        /// * `code`: A syntactically valid class method declaration.
        /// * `expected_dot`: A DOT-specified digraph.
        /// # Panics
        /// Panics if the first non-comment node isn't a `method_declaration` or the provided DOT
        /// snippet is invalidly specified.
        pub fn new(code: &str, expected_dot: &str) -> Self {
            let pre_validation = TsTree::new(code, Language::Java);
            let binding = pre_validation.tree();
            if binding.root_node().has_error() {
                panic!("provided Java contains invalid syntax");
            }
            let mut cursor = binding.walk();
            // Ensure that the first non-comment node is a `method_declaration`
            for child in binding.root_node().children(&mut cursor) {
                match child.kind() {
                    "block_comment" | "line_comment" => continue,
                    "method_declaration" => break,
                    _ => panic!("snippet must start with a method declaration node"),
                }
            }

            let (mut rt, tree) = setup(code);
            let method_decl = tree.find_named_nodes(None, Some("method_declaration"))[0];

            let tsn_bridge = rt.bridge_ts_node();
            let method_decl_id = tsn_bridge.borrow().get_id(method_decl).unwrap();
            // Create the JavaScript graph, and then return the adjacency list `Map` so we can inspect it.
            // language=javascript
            let script = format!(
                "\
const methodFlow = new {}(getNode({}));
methodFlow.graph.adjacencyList;
",
                CLASS_NAME, method_decl_id
            );
            let script = compile_script(&mut rt.v8_handle_scope(), &script).unwrap();
            let full = rt
                .scoped_execute(
                    &script,
                    |sc, val| {
                        let full = v8::Local::<v8::Map>::try_from(val).unwrap();
                        let tsn = &tsn_bridge.borrow();
                        cst_v8_digraph("cst_v8_full", sc, full, &tree, tsn)
                    },
                    None,
                )
                .unwrap();

            let expected = cst_dot_digraph(expected_dot, &tree, None);

            Self { expected, full }
        }
    }

    /// Asserts that the [`Digraph`] generated from the provided `java_code` exactly
    /// equals the specified DOT.
    #[macro_export]
    macro_rules! assert_digraph {
        ($java_code:expr, $expected_dot:expr) => {{
            let test = $crate::analysis::ddsa_lib::js::flow::java::tests::Java::new(
                $java_code,
                $expected_dot,
            );

            if test.expected != test.full {
                println!("{}", test.expected.to_dot());
                println!("{}", test.full.to_dot());
            }
            assert_eq!(test.expected, test.full);
        }};
    }

    /// Asserts that the specified DOT is a subgraph of the full [`Digraph`] generated from the provided `java_code`.
    #[macro_export]
    macro_rules! assert_subgraph {
        ($java_code:expr, $expected_dot:expr) => {{
            let test = $crate::analysis::ddsa_lib::js::flow::java::tests::Java::new(
                $java_code,
                $expected_dot,
            );
            if !test.expected.is_subgraph_of(&test.full) {
                println!("{}", test.expected.to_dot());
                println!("{}", test.full.to_dot());
            }
            assert!(test.expected.is_subgraph_of(test.full));
        }};
    }

    /// In JavaScript, the `findContainingMethod` function on [`CLASS_NAME`] finds the most immediate
    /// method for a given node.
    #[test]
    fn find_containing_method() {
        // language=java
        let source = r#"
public class TestClass {
    // 01: Node outside a method
    private String needle_a = "outside method";

    void dummy() {}

    // 02: Node inside a method
    // 03: Method itself
    void test_02() {
        if (true) {
            String needle_b = "123";
        }
    }

    // 04: Method within an anonymous class
    void test_03() {
        SomeInterface r = new SomeInterface() {
            @override
            public void test_04() {
                String needle_c = "123";
            }
        };
    }
}
"#;
        let (mut rt, tree) = setup(source);
        let methods = tree.find_nodes(None, Some("method_declaration"));
        // Methods
        let (m_dummy, m_test_02, m_test_03, m_test_04) =
            (methods[0], methods[1], methods[2], methods[3]);
        // (Confirm the test is set up correctly by checking the method name)
        for (m_decl, name) in [
            (m_dummy, "dummy"),
            (m_test_02, "test_02"),
            (m_test_03, "test_03"),
            (m_test_04, "test_04"),
        ] {
            assert_eq!(tree.text(field_child(m_decl, "name")), name);
        }

        let needle_a = tree.find_nodes(Some("needle_a"), None)[0];
        let needle_b = tree.find_nodes(Some("needle_b"), None)[0];
        let needle_c = tree.find_nodes(Some("needle_c"), None)[0];

        for (needle, method) in [
            // 01: Node outside a method declaration
            (needle_a, None),
            // 02: Node inside a method declaration
            (needle_b, Some(m_test_02)),
            // 03: Node that is a method declaration
            (m_test_03, Some(m_test_03)),
            // 04: Node inside a method declaration inside a method declaration (via anonymous class).
            (needle_c, Some(m_test_04)),
        ] {
            let nid = rt.bridge_ts_node().borrow().get_id(needle).unwrap();
            let expected = method
                .map(|n| format!("{}", rt.bridge_ts_node().borrow().get_id(n).unwrap()))
                .unwrap_or("undefined".to_string());

            let script = format!("{}.findContainingMethod(getNode({}))?.id;", CLASS_NAME, nid);
            let script = compile_script(&mut rt.v8_handle_scope(), &script).unwrap();
            let exe_result = rt.scoped_execute(&script, |sc, v| v.to_rust_string_lossy(sc), None);
            assert_eq!(exe_result.unwrap(), expected);
        }
    }

    #[test]
    fn op_parse_bin_expr_operator() {
        let cases = [
            // Normal case
            (r#""abc" + "def""#, BinOp::Add),
            // Block comment interspersed
            (r#""abc" /* comment1 */ + "def""#, BinOp::Add),
            // Line comment interspersed
            ("\"abc\"\n\n// comment1\n+\n\"def\"", BinOp::Add),
            // Other operator
            (r#"123 * 456"#, BinOp::Ignored),
        ];
        for (code, expected) in cases {
            let tree = get_tree(code, &Language::Java).unwrap();
            let bin_op = tree.root_node().child(0).unwrap().child(0).unwrap();
            assert_eq!(bin_op.kind(), "binary_expression", "test invariant broken");
            assert_eq!(get_binary_expression_operator(bin_op), Some(expected));
        }
    }

    /// The [`BinOp`] enum numbering should be consistent between Rust and JavaScript.
    #[test]
    fn bin_expr_op_js_synchronization() {
        let tests = [BinOp::Ignored, BinOp::Add];
        let mut rt = cfg_test_runtime();
        let scope = &mut rt.handle_scope();
        for rust_kind in tests {
            let js_const = match rust_kind {
                BinOp::Ignored => "BIN_EXPR_OP_IGNORED",
                BinOp::Add => "BIN_EXPR_OP_ADD",
            };
            let js_value = try_execute(scope, &format!("{};", js_const)).unwrap();
            assert!(js_value.is_number());
            assert_eq!(rust_kind as u32, js_value.uint32_value(scope).unwrap());
        }
    }
}

#[cfg(test)]
mod tests_taint_graph {
    use crate::{assert_digraph, assert_subgraph};

    /// The params to a method are used to describe the first definition of that identifier.
    #[test]
    fn method_decl_params_initial_definition() {
        assert_digraph!(
            // language=java
            "\
void method(String param_A, String... param_B) {
    param_A;
    param_B;
}
",
            // language=dot
            r#"
strict digraph full {
    param_A_0 [text=param_A,line=1]
    param_A_1 [text=param_A,line=2]
    param_B_0 [text=param_B,line=1]
    param_B_1 [text=param_B,line=3]

    param_A_1 -> param_A_0 [kind=dependence]
    param_B_1 -> param_B_0 [kind=dependence]
}
"#
        );
    }

    ///////////////////////////////////////////////////////////////////////////
    // Expressions
    ///////////////////////////////////////////////////////////////////////////

    #[test]
    fn argument_list() {
        assert_subgraph!(
            // language=java
            "\
void method() {
    test_01(1, var_A, var_B);
}
",
            // language=dot
            r#"
strict digraph {
    var_A
    var_B
    argList [text="*",cstkind=argument_list]

    argList -> var_B [kind=dependence]
    argList -> var_A [kind=dependence]
}
"#
        );
    }

    #[test]
    fn array_access() {
        assert_subgraph!(
            // language=java
            "\
void method() {
    var_A[2];
}
",
            // language=dot
            r#"
strict digraph {
    var_A
    arrayAccess [text="*",cstkind=array_access]

    arrayAccess -> var_A [kind=dependence]
}
"#
        )
    }

    /// array_creation_expression
    /// array_initializer
    #[test]
    fn array_creation_expression_array_initializer() {
        assert_digraph!(
            // language=java
            "\
void method() {
    new String[]{var_A, \"abc\", var_B};
}
",
            // language=dot
            r#"
strict digraph full {
    var_A
    var_B
    arrayInit [text="*",cstkind=array_initializer]
    arrayCreation [text="*",cstkind=array_creation_expression]

    arrayCreation -> arrayInit [kind=dependence]
    arrayInit -> var_A [kind=dependence]
    arrayInit -> var_B [kind=dependence]
}
"#
        );
    }

    #[test]
    fn assignment_expr() {
        assert_digraph!(
            // language=java
            "\
void method() {
    var_A = 123;
    var_B = var_C;
}
",
            // language=dot
            r#"
strict digraph full {
    var_A
    var_B
    var_C
    123 [cstkind="*"]

    var_B -> var_C [kind=assignment]
    var_A -> 123 [kind=assignment]
}
"#
        );
    }

    #[test]
    fn binary_expression() {
        assert_digraph!(
            // language=java
            r#"
void method() {
    var_A + "abc" + var_B;
}
"#,
            // language=dot
            r#"
strict digraph full {
    var_A
    var_B
    outerBinExpr [text="var_A + \"abc\" + var_B",cstkind=binary_expression]
    innerBinExpr [text="var_A + \"abc\"",cstkind=binary_expression]

    outerBinExpr -> var_B [kind=dependence]
    outerBinExpr -> innerBinExpr [kind=dependence]
    innerBinExpr -> var_A [kind=dependence]
}
"#
        );
    }

    #[test]
    fn cast_expression() {
        assert_digraph!(
            // language=java
            "\
void method() {
    (String) var_A;
}
",
            // language=dot
            r#"
strict digraph full {
    var_A
    castExpr [text="*",cstkind=cast_expression]

    castExpr -> var_A [kind=dependence]
}
"#
        );
    }

    #[test]
    fn method_invocation() {
        assert_digraph!(
            // language=java
            "\
void method() {
    someMethod();
}
",
            // language=dot
            r#"
strict digraph full { }
"#
        );

        assert_digraph!(
            // language=java
            "\
void method() {
    join(\", \", var_A);
}
",
            // language=dot
            r#"
strict digraph full {
    var_A
    joinArgList [text="*",cstkind=argument_list]
    join [text="*",cstkind=method_invocation]

    join -> joinArgList [kind=dependence]
    joinArgList -> var_A [kind=dependence]
}
"#
        );
    }

    ///////////////////////////////////////////////////////////////////////////
    // Statements
    ///////////////////////////////////////////////////////////////////////////

    #[test]
    fn local_var_decl() {
        assert_digraph!(
            // language=java
            "\
void method() {
    String var_A = \"abc\";
}
",
            // language=dot
            r#"
strict digraph full {
    var_A
    stringLit [text="*",cstkind=string_literal]

    var_A -> stringLit [kind=assignment]
}
"#
        );

        assert_digraph!(
            // language=java
            "\
void method() {
    String var_A = var_B;
}
",
            // language=dot
            r#"
strict digraph full {
    var_A
    var_B

    var_A -> var_B [kind=assignment]
}
"#
        );
    }

    ///////////////////////////////////////////////////////////////////////////
    // Miscellaneous
    ///////////////////////////////////////////////////////////////////////////

    /// Unreachable expressions do not add to the graph.
    #[test]
    fn stmt_list_unreachable() {
        // language=java
        let break_statement = "\
void method() {
    switch (someValue) {
        case 1:
        case 2:
            break;
        default:
            int var_A = 123;
            break;
            int var_B = 456;
    }
}
";
        // language=java
        let throw_statement = "\
void method() {
    try {
        int var_A = 123;
        throw new SampleException();
        int var_B = 456;
    } catch(SampleException e) {
        // ...
    }
}
";
        // language=java
        let continue_statement = "\
void method() {
    while (isActive) {
        int var_A = 123;
        continue;
        int var_B = 456;
    }
}
";

        for java in [break_statement, continue_statement, throw_statement] {
            assert_digraph!(
                java,
                // language=dot
                r#"
    strict digraph full {
        var_A
        123 [cstkind="*"]

        var_A -> 123 [kind=assignment]
    }
    "#
            );
        }
    }
}

/// Graph fidelity reductions that were artificially introduced for performance.
#[cfg(test)]
mod tests_optimizations {
    use crate::assert_digraph;

    /// Binary expressions are ignored unless they use the addition operator, even if there is a nested
    /// addition expression.
    #[test]
    fn binary_expression_ignores_non_addition() {
        assert_digraph!(
            // language=java
            r#"
void method() {
    // Note that we never process the inner (<var_A> + <var_B>) addition binary expression
    // because it is the child of a non-addition binary expression: (<var_A + var_B> - <var_C>)
    var_A + var_B - var_C;
}
"#,
            // language=dot
            r#"
strict digraph full { }
"#
        );
    }
}

/// Graph fidelity reductions that were artificially introduced for implementation simplicity.
#[cfg(test)]
mod tests_artificial_limitations {
    use crate::{assert_digraph, assert_subgraph};

    /// Anonymous classes are not parsed.
    #[test]
    fn anonymous_classes_unsupported() {
        assert_digraph!(
            // language=java
            "\
void method() {
    SomeInterface var_A = new SomeInterface() {
        @override
        public int anon_class_method() {
            return 123 + 456;
        }
    };
}
",
            // language=dot
            r#"
strict digraph full {
    var_A
    objCreationExpr [text="*",cstkind=object_creation_expression]

    var_A -> objCreationExpr [kind=assignment]
}
"#
        );
    }

    #[test]
    fn assignment_expr_assume_equals() {
        assert_digraph!(
            // language=java
            "\
void method() {
    var_A += var_B;
}
",
            // language=dot
            r#"
strict digraph full {
    var_A
    var_B

    // Because the above statement is equivalent to:
    // var_A = var_A + var_B;
    //
    // We should have:
    // var_A -> var_B [kind=dependence]
    //
    // However, because of our simplification that assumes an `=`, we have:
    var_A -> var_B [kind=assignment]
}
"#
        );
    }

    /// We currently do not consider separate branches of control flow as independent, mutually
    /// exclusive possibilities. As such, we end up treating the last branch as the "most recent" definition.
    #[test]
    fn control_flow_merge_point_unsupported() {
        assert_digraph!(
            // language=java
            "\
void method() {
    String var_B;
    if (var_A) {
        var_B = alt_01;
    } else {
        var_B = alt_02;
    }
    var_B;
}
",
            // language=dot
            r#"
strict digraph full {
    alt_01
    alt_02
    // var_b_0 [text="var_B",line=2]
    var_b_1 [text="var_B",line=4]
    var_b_2 [text="var_B",line=6]
    var_b_3 [text="var_B",line=8]

    var_b_1 -> alt_01 [kind=assignment]
    var_b_2 -> alt_02 [kind=assignment]

    // We _ideally_ would have:
    // var_b_3 -> var_b_2 [kind=dependence]
    // var_b_3 -> var_b_1 [kind=dependence]

    // But our current approach limits us to:
    var_b_3 -> var_b_2 [kind=dependence]
}
"#
        );

        assert_digraph!(
            // language=java
            "\
void method() {
    String var_B;
    switch (var_A) {
        case 1:
        case 2:
            var_B = alt_01;
            break;
        default:
            var_B = alt_02;
            break;
    }
    var_B;
}
",
            // language=dot
            r#"
strict digraph full {
    alt_01
    alt_02
    // var_b_0 [text="var_B",line=2]
    var_b_1 [text="var_B",line=6]
    var_b_2 [text="var_B",line=9]
    var_b_3 [text="var_B",line=12]

    var_b_1 -> alt_01 [kind=assignment]
    var_b_2 -> alt_02 [kind=assignment]

    // We _ideally_ would have:
    // var_b_3 -> var_b_2 [kind=dependence]
    // var_b_3 -> var_b_1 [kind=dependence]

    // But our current approach limits us to:
    var_b_3 -> var_b_2 [kind=dependence]
}
"#
        );
    }

    /// `field_access` nodes are passed through, but not analyzed.
    #[test]
    fn field_access_unsupported() {
        assert_digraph!(
            // language=java
            "\
void method() {
    String var_A = var_B.field;
}
",
            // language=dot
            r#"
strict digraph full {
    var_A
    fieldAccess [text="*",cstkind=field_access]

    var_A -> fieldAccess [kind=assignment]
}
"#
        );
    }

    /// `lambda_expression` nodes are parsed but not analyzed.
    #[test]
    fn lambda_expression_unsupported() {
        assert_digraph!(
            // language=java
            "\
void method() {
    String var_A = ((Supplier<String>) () -> var_B).get();
}
",
            // language=dot
            r#"
strict digraph full {
    var_A
    methodInvocation [text="*",cstkind=method_invocation]

    var_A -> methodInvocation [kind=assignment]
}
"#
        );
    }

    /// Lexical scopes are not supported.
    #[test]
    fn variable_scoping_unsupported() {
        assert_subgraph!(
            // language=java
            "\
void method() {
    int var_A = 123;
    if (condition) {
        String var_A = var_B;
    }
    int var_C = var_A;
}
",
            // language=dot
            r#"
strict digraph {
    var_A_0 [text=var_A,line=2]
    var_A_1 [text=var_A,line=4]
    var_A_2 [text=var_A,line=6]
    var_B
    var_C

    var_A_1 -> var_B [kind=assignment]
    var_C -> var_A_2 [kind=assignment]

    // This relationship is incorrect (and is a side effect of not supporting variable scoping).
    var_A_2 -> var_A_1 [kind=dependence]
    //////////
}
"#
        );
    }
}

/// Special case, manual simplifications that create graph edges. These may introduce false positives.
#[cfg(test)]
mod tests_special_case_simplifications {
    use crate::assert_digraph;

    /// We simplify and say that the return value of a method call on a variable is tainted by that variable.
    #[test]
    fn method_call_return_object() {
        assert_digraph!(
            // language=java
            "\
void method() {
    var_A = var_B.getHeader(\"X-Header-Name\");
}
",
            // language=dot
            r#"
strict digraph full {
    var_A
    var_B
    methodCall [text="*",cstkind=method_invocation]

    // The simplification:
    methodCall -> var_B [kind=dependence]
    //////////

    var_A -> methodCall [kind=assignment]
}
"#
        );
    }

    /// We simplify and say that any argument that flows into any method call taints the return value.
    #[test]
    fn method_call_return_input_args() {
        assert_digraph!(
            // language=java
            "\
void method() {
    var_A = getHeader(\"abc\", var_B, var_C);
}
",
            // language=dot
            r#"
strict digraph full {
    var_A
    var_B
    var_C
    methodCall [text="*",cstkind=method_invocation]
    argList [text="*",cstkind=argument_list]

    // The simplification:
    argList -> var_B [kind=dependence]
    argList -> var_C [kind=dependence]
    //////////

    methodCall -> argList [kind=dependence]
    var_A -> methodCall [kind=assignment]
}
"#
        );
    }
}
