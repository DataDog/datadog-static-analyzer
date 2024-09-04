// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

import { Digraph, EDGE_ASSIGNMENT, EDGE_DEPENDENCE, vertexId } from "ext:ddsa_lib/flow/graph";

const { op_java_get_bin_expr_operator } = Deno.core.ops;

/**
 * A graph describing the flow of variables within a single method.
 *
 * # Limitations
 * This graph cuts corners in the interest of implementation simplicity:
 *
 * ## Name resolution and scoping
 * Variable scopes are unsupported.
 * For example:
 * ```java
 * int someVariable = 123;
 * if (shouldProceed) {
 *     int someVariable = 456;
 *     System.out.println(value);
 *     someVariable = 789;
 * }
 * System.out.println(someVariable); // At this point, we'll think `someVariable` is 789.
 * ```
 *
 * ## Type resolution
 * Type resolution is unsupported.
 *
 * ## Control flow expressions
 * Return values for expressions aren't formally represented, and thus phi nodes are not created for
 * expressions that use conditional blocks.
 * For example:
 * ```java
 * int someVariable = switch (value) {
 *     case 1 -> alt0;
 *     case 2 -> alt1;
 *     default -> alt2;
 * }
 * // Here, `someVariable` is not assigned to a phi node (rather, the dependence edges are drawn directly)
 * ```
 */
export class MethodFlow {
    /**
     * @param {TreeSitterNode} methodDecl The node of a `method_declaration`.
     */
    constructor(methodDecl) {
        if (methodDecl.cstType !== "method_declaration") {
            throw new Error("MethodFlow can only be constructed from a `method_declaration` node.");
        }

        /**
         * The `method_declaration` node this {@link MethodFlow} represents.
         * @type {TreeSitterNode}
         * @private
         */
        this.methodDecl = methodDecl;

        /**
         * A graph of taint propagation.
         * @type {Digraph}
         */
        this.graph = new Digraph();

        /**
         * The traversal context
         * @type {TraversalContext}
         */
        this.context = {
            lastTaintSource: undefined,
            scopeStack: [],
            conditionalAncestorBlocks: 0,
        };

        this.visitMethodDecl(methodDecl);
    }

    /**
     * Returns the {@link TreeSitterNode} of the method declaration that contains the provided `node`, if it exists.
     * @param {TreeSitterNode} node
     * @returns {TreeSitterNode | undefined} A node with `cstType === "method_declaration"`.
     */
    static findContainingMethod(node) {
        let current = node;
        while (current.cstType !== "method_declaration") {
            current = globalThis.ddsa.getParent(current);
            if (current === undefined) {
                // If we're at the tree root and haven't found a `method_declaration` yet, the original `node` was not
                // nested within a method. Return undefined.
                return undefined;
            }
        }
        return current;
    }


    /**
     * Visits the provided `node`.
     * @param {TreeSitterNode} node
     */
    visit(node) {
        switch (node.cstType) {
            // Expressions
            case "argument_list":
                this.visitArgList(node);
                break;
            case "array_access":
                this.visitArrayAccessExpr(node);
                break;
            case "array_creation_expression":
                this.visitArrayCreationExpr(node);
                break;
            case "array_initializer":
                this.visitArrayInitExpr(node);
                break;
            case "assignment_expression":
                this.visitAssignExpr(node);
                break;
            case "binary_expression":
                this.visitBinExpr(node);
                break;
            case "cast_expression":
                this.visitCastExpr(node);
                break;
            case "field_access":
                this.visitFieldAccess(node);
                break;
            case "identifier":
                this.visitIdentifier(node);
                break;
            case "lambda_expression":
                this.visitLambdaExpr(node);
                break;
            case "method_invocation":
                this.visitMethodCall(node);
                break;
            case "method_reference":
                this.visitMethodRefExpr(node);
                break;
            case "object_creation_expression":
                this.visitObjCreationExpr(node);
                break;
            case "parenthesized_expression":
                this.visitParensExpr(node);
                break;
            case "template_expression":
                this.visitTemplateExpr(node);
                break;
            case "ternary_expression":
                this.visitTernaryExpr(node);
                break;

            // Statements
            case "block":
                this.visitBlockStmt(node);
                break;
            case "do_statement":
                this.visitDoStmt(node);
                break;
            case "enhanced_for_statement":
                this.visitEnhancedForStmt(node);
                break;
            case "expression_statement":
                this.visitExprStmt(node);
                break;
            case "for_statement":
                this.visitForStmt(node);
                break;
            case "if_statement":
                this.visitIfStmt(node);
                break;
            case "labeled_statement":
                this.visitLabeledStmt(node);
                break;
            case "local_variable_declaration":
                this.visitLocalVarDecl(node);
                break;
            case "method_declaration":
                // [simplification] We do not support methods defined within other methods. Thus, while we
                // do have `visitMethodDecl`, we do not want to invoke it here.
                break;
            case "switch_expression":
                this.visitSwitchExpr(node);
                break;
            case "synchronized_statement":
                this.visitSynchronizedStmt(node);
                break;
            case "try_statement":
                this.visitTryStmt(node);
                break;
            case "try_with_resources_statement":
                // TODO(JF): After scoped variable support: add (resource_specification (resource)+) to defs
                break;
            case "while_statement":
                this.visitWhileStmt(node);
                break;

            // Literals:
            case "binary_integer_literal":
            case "character_literal":
            case "decimal_integer_literal":
            case "decimal_floating_point_literal":
            case "false":
            case "hex_floating_point_literal":
            case "hex_integer_literal":
            case "null_literal":
            case "octal_integer_literal":
            case "string_literal":
            case "true":
                this.visitLiteral(node);
                break;
            // Jump statements (Handled within individual visit functions)
            case "break_statement":
            case "return_statement":
            case "throw_statement":
            case "continue_statement":
            case "yield_statement":
                break;
            // Comments
            case "block_comment":
            case "line_comment":
                break;
            // Not handled:
            case "class_declaration":
                break;
            default:
                // (Support for other node types has not been implemented)
                break;
        }
    }

    ///////////////////////////////////////////////////////////////////////////
    // Visitors
    ///////////////////////////////////////////////////////////////////////////

    // Expressions
    //////////////

    /**
     * Visits an `argument_list`.
     * ```java
     *     example_01();
     * //            ^^
     *     example_02(1, 2, 3);
     * //            ^^^^^^^^^
     * ```
     * ```
     * (argument_list (_)*)
     * ```
     * @param {TreeSitterNode} node
     */
    visitArgList(node) {
        const children = ddsa.getChildren(node);
        for (const child of children) {
            this.visit(child);
            this.propagateLastTaint(node);
        }
    }

    /**
     * Visits an `array_access`.
     * ```java
     *     String example_01 = data[2];
     * //  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^
     * ```
     * ```
     * (array_access array: (_) index: (_))
     * ```
     * @param {TreeSitterNode} node
     */
    visitArrayAccessExpr(node) {
        // (Note: the `array` field can be an arbitrary expression)
        const children = ddsa.getChildren(node);
        const arrayIdx = findFieldIndex(children, 0, "array");
        const array = children[arrayIdx];

        this.visit(array);
        this.propagateLastTaint(node);
    }

    /**
     * Visits an `array_creation_expression`.
     * ```java
     * var example_01 = new String[]{"hello", someVar};
     * //               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
     * var example_02 = new byte[1024];
     * //               ^^^^^^^^^^^^^^
     * ```
     * ```
     * (type: (_) dimensions: (dimensions) <value: (array_initializer)>?)
     * ```
     * @param {TreeSitterNode} node
     */
    visitArrayCreationExpr(node) {
        // Each value needs to be visited, as it can contain an arbitrary expression.
        const children = ddsa.getChildren(node);

        const valueIdx = findFieldIndex(children, 2, "value");
        if (valueIdx !== -1) {
            const value = children[valueIdx];
            this.visit(value);
            this.propagateLastTaint(node);
        }
    }

    /**
     * Visits an `array_initializer`.
     * ```java
     * var example_01 = new String[]{"hello", someVar};
     * //                           ^^^^^^^^^^^^^^^^^^
     * ```
     * ```
     * (array_initializer (_)*)
     * ```
     * @param {TreeSitterNode} node
     */
    visitArrayInitExpr(node) {
        // Each child is a different expression:
        const children = ddsa.getChildren(node);

        for (const child of children) {
            this.visit(child);
            this.propagateLastTaint(node);
        }
    }

    /**
     * Visits an `assignment_expression`.
     * ```java
     *     example_01 = 123;
     * //  ^^^^^^^^^^^^^^^^^
     *     example_02 += "some string";
     * //  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^
     * ```
     * ```
     * (assignment_expression left: (identifier) right: (_))
     * ```
     * @param {TreeSitterNode} node
     */
    visitAssignExpr(node) {
        const children = ddsa.getChildren(node);

        const rhsIdx = findFieldIndex(children, 1, "right");
        const rhsExpr = children[rhsIdx];
        this.visit(rhsExpr);

        const lhsIdx = findFieldIndex(children, 0, "left");
        const name = children[lhsIdx];

        // [simplification]: assume the operator in this case is an `=`, making this a true assignment.
        //                   (if the operator was, e.g. `+=`, we would have a "dependence", not assignment).
        // The current definition for "name" is now `rhsExpr`.
        this.graph.addTypedEdge(vertexId(name), vertexId(rhsExpr), EDGE_ASSIGNMENT);
        this.markCurrentDefinition(name.text, name);
        // Reset the current taint status.
        const _ = this.takeLastTainted();
    }

    /**
     * Visits a `binary_expression`.
     * ```java
     *     example_01 + b;
     * //  ^^^^^^^^^^^^^^
     * ```
     * ```
     * (binary_expression left: (_) right: (_))
     * ```
     * @param {TreeSitterNode} node
     */
    visitBinExpr(node) {
        /** @type {BinExprOp | -1} */
        const operator = op_java_get_bin_expr_operator(node.id);
        // Only certain binary expressions can propagate taint:
        switch (operator) {
            // Strings can be concatenated/mutated via an addition operation.
            case BIN_EXPR_OP_ADD: {
                const _ = this.takeLastTainted();

                const children = ddsa.getChildren(node);

                // (start index is 1 to account for preceding "left" field)
                const rightIdx = findFieldIndex(children, 1, "right");
                const right = children[rightIdx];
                this.visit(right);
                this.propagateLastTaint(node);

                const leftIdx = findFieldIndex(children, 0, "left");
                const left = children[leftIdx];
                this.visit(left);
                this.propagateLastTaint(node);

                break;
            }
            default:
                break;
        }
    }

    /**
     * Visits a `cast_expression`.
     * ```java
     * Object upStr = "Hello World";
     * // Downcasting:
     * String name = (String) upStr;
     * //            ^^^^^^^^^^^^^^
     * // Casting:
     * Float temperature = (float) 98.6;
     * //                  ^^^^^^^^^^^^
     * ```
     * ```
     * (cast_expression type: (_) value: (_))
     * ```
     * @param {TreeSitterNode} node
     */
    visitCastExpr(node) {
        const children = ddsa.getChildren(node);

        const valueIdx = findFieldIndex(children, 1, "value");
        const value = children[valueIdx];
        this.visit(value);
        this.propagateLastTaint(node);
    }

    /**
     * Visits a `field_access`.
     * ```java
     *     example_01.field = 123;
     * //  ^^^^^^^^^^^^^^^^
     *     example_02.inner_01.inner_02.someMethod();
     * //  ^^^^^^^^^^^^^^^^^^^
     * //  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^
     * ```
     * ```
     * (field_access object: (_) field: (_))
     * ```
     * @param {TreeSitterNode} _node
     */
    visitFieldAccess(_node) {
        // [simplification]: Given that we are operating on a CST and don't have name resolution, it's not
        // straightforward to determine the nature of the field access. Thus, we ignore it.
    }

    /**
     * Visits an `identifier`.
     * ```java
     * // Non-exhaustive examples:
     *     int someName = 1234;
     * //      ^^^^^^^^
     *     doAction( someParam, another );
     * //  ^^^^^^^^  ^^^^^^^^^  ^^^^^^^
     * ```
     * ```
     * (identifier)
     * ```
     * @param {TreeSitterNode} node
     */
    visitIdentifier(node) {
        const currentDef = this.resolveVariableAt(node.text, this.context.scopeStack.length);
        // If this identifier has a known definition, create a dependence edge.
        if (currentDef !== undefined) {
            // Given the following code:
            // ```java
            // int y = 10;          // L1
            // y = 20;              // L2
            // int z = y + 5;       // L3
            // ```
            // If we are visiting the expression on line 3:
            // We intuitively know that the `y` on L3 refers to the `y` on L2, not the `y` on L1.
            //
            // To establish this fact within our graph, we create a dependence edge from L3's `identifier` node to L2's.
            //
            // And then to our analysis, we can effectively have:
            // ```java
            // int y_1 = 10;        // L1
            // int y_2 = 20;        // L2
            // int z_1 = y_2 + 5;   // L3
            // ```
            this.graph.addTypedEdge(vertexId(node), currentDef, EDGE_DEPENDENCE);
        } else {
            // If this is a valid program and there is no known definition here, it is either that:
            // 1. We're visiting this `identifier` recursively within a variable declarator visitor.
            //    In this case, an `EDGE_ASSIGNMENT` will be created by _that_ visitor (i.e. after this `visitIdentifier`).
            // 2. The identifier has a definition outside our tracked scope.
        }
        // Because we're operating on a CST and not an AST, we can't easily distinguish the semantic context of an `identifier` node:
        // For example:
        // ```java
        // String x = "SELECT * FROM users WHERE name = " + someUserInput;
        //                                                  ^^^^^^^^^^^^^ 01. `identifier`
        // System.out.println("Done");
        //            ^^^^^^^ 02. `identifier`
        //        ^^^ 03. `identifier`
        // ^^^^^^ 04. `identifier`
        // ```
        //
        // We want to track #01 with `this.markLastTainted` (as here, the `identifier` node represents a variable).
        // However, we _don't_ want to mark #02, #03, #04 as "tainted".
        //
        // The way we ensure this is by only intentionally calling "visitIdentifier" from relevant visitors (e.g. `field_access`)
        // if we've determined that the `identifier` actually represents a variable.
        this.markLastTainted(node);
    }

    /**
     * Visits one of:
     * * `binary_integer_literal`
     * * `character_literal`
     * * `decimal_integer_literal`
     * * `decimal_floating_point_literal`
     * * `false`
     * * `hex_floating_point_literal`
     * * `hex_integer_literal`
     * * `null_literal`
     * * `octal_integer_literal`
     * * `string_literal`
     * * `true`
     *
     * ```
     * (_literal (_)*)
     * ```
     * @param {TreeSitterNode} node
     */
    visitLiteral(node) {
        // [simplification]: We currently don't utilize techniques like constant propagation, so literals are ignored.
    }

    /**
     * Visits a `lambda_expression`.
     * ```java
     *     example_01.forEach((v) -> v + "!");
     * //                     ^^^^^^^^^^^^^^
     *     example_02 = ((Supplier<String>) () -> { return "abc"; }).get();
     * //                                   ^^^^^^^^^^^^^^^^^^^^^^^
     * ```
     * ```
     * (lambda_expression parameters: (_) body: (_))
     * ```
     * @param {TreeSitterNode} node
     */
    visitLambdaExpr(node) {
        // [simplification]: Ignore this node
    }

    /**
     * Visits a `method_invocation`.
     * ```java
     *     example_01.someMethod();
     * //  ^^^^^^^^^^^^^^^^^^^^^^^
     *     String.join(", ", example_02);
     * //  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
     * ```
     * ```
     * (method_invocation <object: (_)>? name: (identifier)  arguments: (argument_list))
     * ```
     * @param {TreeSitterNode} node
     */
    visitMethodCall(node) {
        const children = ddsa.getChildren(node);
        const objIdx = findFieldIndex(children, 0, "object");

        // [simplification]: Ignore the "name" field (we don't do name or type resolution).

        const argsIdx = findFieldIndex(children, objIdx + 1, "arguments");
        const args = children[argsIdx];
        this.visitArgList(args);

        // [simplification]: Propagate tainted arguments as if they _always_ flow through into the return value
        // of the method (this is clearly not always the case).
        this.propagateLastTaint(node);

        // [(identifier) (field_access)]
        const obj = children[objIdx];
        if (obj?.cstType === "identifier") {
            // [simplification]: If the node could represent a local variable, propagate taint as if that local variable
            // always taints the return value of an instance method (this is clearly not always the case).
            this.visitIdentifier(obj);
            this.propagateLastTaint(node);
        }
    }

    /**
     * Visits a `method_reference`.
     * ```java
     *     example_01.forEach(System.out::println);
     * //                     ^^^^^^^^^^^^^^^^^^^
     * ```
     * ```
     * (method_reference (_)+)
     * ```
     * @param {TreeSitterNode} node
     */
    visitMethodRefExpr(node) {
        // [simplification]: Ignore this node
    }

    /**
     * Visits an `object_creation_expression`.
     * ```java
     *     new Example_01();
     * //  ^^^^^^^^^^^^^^^^
     *     new Example_02().new InnerClass();
     * //  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
     * ```
     * ```
     * (object_creation_expression (object_creation_expression)? type: (_) arguments: (argument_list))
     * ```
     * @param {TreeSitterNode} node
     */
    visitObjCreationExpr(node) {
        // [simplification]: Propagate arguments as if they _always_ flow through into the return value
        // of the constructor.
        const children = ddsa.getChildren(node);

        const argumentsIdx = findFieldIndex(children, 1, "arguments");
        const args = children[argumentsIdx];
        this.visitArgList(args);
        this.propagateLastTaint(node);
    }

    /**
     * Visits a `parenthesized_expression`.
     * ```java
     * int example_01 = (1234);
     * //               ^^^^^^
     * ```
     * ```
     * (parenthesized_expression (_))
     * ```
     *
     * @param {TreeSitterNode} node
     */
    visitParensExpr(node) {
        const children = ddsa.getChildren(node);
        for (const child of children) {
            // The first non-comment node is the wrapped expression.
            if (!isCommentNode(child)) {
                this.visit(child);
                this.propagateLastTaint(node);
                break;
            }
        }
    }

    /**
     * Visits a `template_expression`.
     * ```java
     * String query = STR."SELECT * FROM users where username='\{userInput}'";
     * //             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
     * ```
     * ```
     * (template_expression template_processor: (identifier) template_argument: (string_literal))
     * ```
     *
     * @param {TreeSitterNode} node
     */
    visitTemplateExpr(node) {
        const children = ddsa.getChildren(node);
        const processorIdx = findFieldIndex(children, 0, "template_processor");

        // To be conservative, we currently only attempt to parse `STR` and `FMT`.
        const processor = children[processorIdx];
        switch (processor.text) {
            case "STR":
            case "FMT":
                break;
            default:
                return;
        }

        const templateArgIdx = findFieldIndex(children, processorIdx + 1, "template_argument");
        const templateArg = children[templateArgIdx];

        const stringLitChildren = ddsa.getChildren(templateArg);
        // (string_literal [(string_fragment) (string_interpolation (_))]*)
        for (const stringLitChild of stringLitChildren) {
            if (stringLitChild.cstType === "string_interpolation") {
                // (string_interpolation (_))
                const interChildren = ddsa.getChildren(stringLitChild);
                for (const child of interChildren) {
                    if (!isCommentNode(child)) {
                        this.visit(child);
                        this.propagateLastTaint(node);
                    }
                }
            }
        }
    }

    /**
     * Visits a `ternary_expression`.
     * ```java
     *     example_01 = isValid ? someVar : otherVar;
     * //               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^
     * ```
     * ```
     * (ternary_expression condition: (_) consequence: (_) alternative: (_))
     * ```
     *
     * # Note
     * [simplification]: This uses the same control flow logic as {@link MethodFlow.visitIfStmt}.
     *
     * @param {TreeSitterNode} node
     */
    visitTernaryExpr(node) {
        const children = ddsa.getChildren(node);
        // In the `condition` field, external variables can be mutated, but this is a corner case we
        // explicitly disregard, and so we only process the `consequence`.
        ignoreMutatingField(/* condition */);

        // See `visitIfStmt` for a caveat on how we're handling branches.
        const conseqIdx = findFieldIndex(children, 1, "consequence");
        const conseq = children[conseqIdx];
        this.visit(conseq);
        this.propagateLastTaint(node);

        const altIdx = findFieldIndex(children, conseqIdx + 1, "alternative");
        const alternative = children[altIdx];
        this.visit(alternative);
        this.propagateLastTaint(node);
    }

    // Statements
    //////////////

    /**
     * Visits a `block`.
     * ```java
     * // Non-exhaustive examples:
     *     void myMethod()
     * //  vvvvvvvvvvvvvvvv
     *     {
     *         // some code
     *     }
     * //  ^^^^^^^^^^^^^^^^
     * ```
     * ```
     * (block (_)*)
     * ```
     *
     * # Control Flow
     * Semantically, this visitor treats the syntactic block as a CFG "scope block".
     * If the syntactic block represents a CFG conditional block, this function should not be used. Rather,
     * the caller must manually enter and exit the block:
     * ```js
     * this.enterBlock(true)
     * // ...
     * this.exitBlock();
     * ```
     *
     * @param {TreeSitterNode} node
     */
    visitBlockStmt(node) {
        // By default, assume a syntactic block is a scope block.
        this.enterBlock(false);
        this._innerVisitBlockStmt(node);
        this.exitBlock();
        // (Ignore the returned scope: this isn't a merge point, so no reconciliation is required).
    }

    /**
     * Visits the children of a `block` CST node.
     * @param {TreeSitterNode} blockNode A `block` CST node.
     */
    _innerVisitBlockStmt(blockNode) {
        const exprStmts = ddsa.getChildren(blockNode);
        this._visitExprStmtList(blockNode, exprStmts);
    }

    /**
     * Visits a list of nodes that are expressions and statements in sequential order.
     * @param {TreeSitterNode} parent An ancestor of {@link nodes} which should receive any tainted return values.
     * @param {Array<TreeSitterNode>} nodes
     */
    _visitExprStmtList(parent, nodes) {
        outer: for (const node of nodes) {
            this.visit(node);
            switch (node.cstType) {
                case "break_statement":
                case "throw_statement":
                case "continue_statement":
                case "return_statement":
                    // All subsequent nodes are unreachable.
                    break outer;
                case "yield_statement": {
                    // Visit children of the yield statement so they can be propagated to `parent`.
                    const yieldChildren = ddsa.getChildren(node);
                    for (const child of yieldChildren) {
                        this.visit(child);
                    }
                    this.propagateLastTaint(parent);
                    // All subsequent nodes are unreachable.
                    break outer;
                }
                default:
                    break;
            }
        }
    }

    /**
     * Visits a `do_statement`.
     * ```java
     *     do { } while (example_01);
     * //  ^^^^^^^^^^^^^^^^^^^^^^^^^^
     * ```
     * ```
     * (do_statement body: (block) condition: (parenthesized_expression))
     * ```
     * @param {TreeSitterNode} node
     */
    visitDoStmt(node) {
        const children = ddsa.getChildren(node);
        const bodyIdx = findFieldIndex(children, 0, "body");
        const body = children[bodyIdx];
        this.visitBlockStmt(body);

        ignoreMutatingField(/* "condition" */);
    }

    /**
     * Visits an `enhanced_for_statement`.
     * ```java
     *     for (String example_01 : arr) { }
     * //  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
     * ```
     * ```
     * (enhanced_for_statement type: (_) name: (identifier) value: (_) body: (block))
     * ```
     * @param {TreeSitterNode} node
     */
    visitEnhancedForStmt(node) {
        const children = ddsa.getChildren(node);
        ignoreMutatingField(/* "value" */);

        const bodyIdx = findFieldIndex(children, 3, "body");
        const body = children[bodyIdx];
        this.visitBlockStmt(body);
    }

    /**
     * Visits an `expression_statement`.
     * ```java
     * // Non-exhaustive examples:
     *     example_01;
     * //  ^^^^^^^^^^^
     *     example_02 + 1234;
     * //  ^^^^^^^^^^^^^^^^^^
     *     example_03.someMethod();
     * //  ^^^^^^^^^^^^^^^^^^^^^^^^
     * ```
     * ```
     * (expression_statement (_))
     * ```
     * @param {TreeSitterNode} node
     */
    visitExprStmt(node) {
        // (NB: The first child cannot be a comment, so it is safe to manually index into this array)
        const innerExpr = ddsa.getChildren(node)[0];
        this.visit(innerExpr);
        const _ = this.takeLastTainted();
    }

    /**
     * Visits a `for_statement`.
     * ```java
     *     for (int i = 0, j = 0, example_01 = 0; i < 3; i++, j += 2) { }
     * //  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
     *     for (;;) { } // example_02
     * //  ^^^^^^^^^^^^
     * ```
     * ```
     * (for_statement <init: (_)>? <condition: (_)>? <update: (_)>* body: (block))
     * ```
     * @param {TreeSitterNode} node
     */
    visitForStmt(node) {
        const children = ddsa.getChildren(node);

        // The index of the first "update" child field detected.
        let updateFieldIdx = -1;

        const len = children.length;
        for (let i = 0; i < len; i++) {
            const child = children[i];
            if (isCommentNode(child)) {
                continue;
            }
            switch (child.fieldName) {
                case "init":
                    this.visit(child);
                    // TODO(JF): After scoped variable support: propagate taint here
                    break;
                case "condition":
                    // noop
                    break;
                case "update":
                    // (We visit "update" fields _after_ the "body" field name to do a rough approximation of the CFG,
                    // so we break within this branch and handle it afterward).
                    if (updateFieldIdx === -1) {
                        updateFieldIdx = i;
                    }
                    break;
                case "body":
                    this.visitBlockStmt(child);
                    break;
                default:
                    throw new Error("unreachable");
            }
        }

        if (updateFieldIdx !== -1) {
            for (let i = updateFieldIdx; i < len; i++) {
                const child = children[i];
                this.visit(child);
                // TODO(JF): After scoped variable support: propagate taint here
            }
        }
    }

    /**
     * Visits an `if_statement`.
     * ```java
     *    if (example_01) { }
     * // ^^^^^^^^^^^^^^^^^^^
     *    if (example_02) { } else { }
     * // ^^^^^^^^^^^^^^^^^^^^^^^^^^^^
     *    if (example_03) { } else if { } else { }
     * // ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
     *    if (example_04) { } else throw new Err(e)
     * // ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
     * ```
     * ```
     * (if_statement
     *     condition: (parenthesized_expression)
     *     consequence: (_)
     *     <alternative: (_)>?)
     * ```
     * @param {TreeSitterNode} node
     */
    visitIfStmt(node) {
        this.enterBlock(true);
        this._innerVisitIfStmt(node);
        this.exitBlock();
    }

    /**
     * Implements the logic of visiting an `if_statement` without creating a control flow conditional block.
     *
     * This is necessary because the CST representation of an "if...else if" statement is
     * recursive, whereas the control flow conditional blocks are vertices on the same level within the CFG:
     * ```java
     *    if (example_01) { } else if (e4) { }
     * // ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
     * //                          ^^^^^^^^^^^
     * ```
     * ```
     * (if_statement
     *      condition: (parenthesized_expression)
     *      consequence: (block)
     *      alternative: (if_statement
     *          condition: (parenthesized_expression)
     *          consequence: (block)
     *      )
     * )
     * ```
     *
     * This function encapsulates any recursion so that {@link MethodFlow.visitIfStmt} can be implemented sequentially.
     *
     * @param {TreeSitterNode} node
     * @private
     */
    _innerVisitIfStmt(node) {
        const children = ddsa.getChildren(node);
        // In the `condition` field, external variables can be mutated, but this is a corner case we
        // explicitly disregard, and so we only process the `consequence`.
        ignoreMutatingField(/* condition */);

        const consequentIdx = findFieldIndex(children, 1, "consequence");
        // (_)
        const consequent = children[consequentIdx];
        this._innerVisitIfStmtConditionalBlock(consequent, BRANCH_TYPE_CONSEQUENT);

        const altIdx = findFieldIndex(children, consequentIdx + 1, "alternative");
        if (altIdx !== -1) {
            // (_)
            const alternative = children[altIdx];
            this._innerVisitIfStmtConditionalBlock(alternative, BRANCH_TYPE_ALTERNATIVE);
        }
    }

    /**
     * A helper for {@link MethodFlow._innerVisitIfStmt} that implements logic to visit a CST node representing
     * the consequent/alternative of an if statement.
     *
     * @param {TreeSitterNode} node
     * @param {BranchSemantic} branchSemantic
     * @private
     */
    _innerVisitIfStmtConditionalBlock(node, branchSemantic) {
        switch (node.cstType) {
            // A semantic "else if" (This requires recursion, so a branching block isn't entered)
            case "if_statement": {
                // to preserve the correct parent.
                this._innerVisitIfStmt(node);
                break;
            }
            // A conditional CFG block that happens to be a CST block.
            case "block": {
                this.enterBranch(branchSemantic);
                this._innerVisitBlockStmt(node);
                this.exitBlock();
                break;
            }
            // A conditional CFG block, but not a CST block:
            // ```java
            // String val = "abc";
            // if (condition) val = "123";
            // ```
            case "expression_statement": {
                this.enterBranch(branchSemantic);
                this.visitExprStmt(node);
                this.exitBlock();
                break;
            }
            // Other CST types (non-exhaustive examples below) are not handled:
            // ```java
            // if (condition) return 123;
            //
            // if (condition) {
            //     val = "xyz";
            // } else throw new Err(e);
            // ```
            default:
                // unimplemented
                break;
        }
    }

    /**
     * Visits a `labeled_statement`.
     * ```java
     * //  vvvvvvvvvvv
     *     example_01:
     *     for (i = 0; i < 3; i++) { }
     * //  ^^^^^^^^^^^^^^^^^^^^^^^^^^^
     * ```
     * ```
     * (labeled_statement (identifier) (_)+)
     * ```
     * @param {TreeSitterNode} node
     */
    visitLabeledStmt(node) {
        const children = ddsa.getChildren(node);
        const len = children.length;
        // Skip the (identifier):
        for (let i = 1; i < len; i++) {
            const child = children[i];
            this.visit(child);
        }
    }

    /**
     * Visits a `local_variable_declaration`.
     * ```java
     *     int example_01 = 1234;
     * //  ^^^^^^^^^^^^^^^^^^^^^^
     *     int example_02 = 1, example_03 = 2;
     * //  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
     *     int example_04;
     * //  ^^^^^^^^^^^^^^^
     * ```
     * ```
     * (local_variable_declaration type: (_) <declarator: (variable_declarator)>+)
     * ```
     * @param {TreeSitterNode} node
     */
    visitLocalVarDecl(node) {
        const children = ddsa.getChildren(node);

        for (let i = 1; i < children.length; i++) {
            const child = children[i];
            if (child.fieldName !== "declarator") {
                continue;
            }

            // (variable_declarator name: (identifier) <value: (_)>?)
            const declaratorChildren = ddsa.getChildren(child);
            const nameIdx = findFieldIndex(declaratorChildren, 0, "name");
            const name = declaratorChildren[nameIdx];

            const valueIdx = findFieldIndex(declaratorChildren, nameIdx + 1, "value");
            // A variable may not be declared with a value.
            if (valueIdx !== -1) {
                const rhsExpr = declaratorChildren[valueIdx];
                this.visit(rhsExpr);
                this.graph.addTypedEdge(vertexId(name), vertexId(rhsExpr), EDGE_ASSIGNMENT);
            }

            this.markCurrentDefinition(name.text, name);
            // Reset the current taint status.
            const _ = this.takeLastTainted();
        }
    }

    /**
     * Visits a `method_declaration`.
     * ```java
     *     void example_01() { }
     * //  ^^^^^^^^^^^^^^^^^^^^^
     *     static void example_02() { }
     * //  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^
     *     void example_03() throws SomeException { }
     * //  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
     *     <T> T example_04(T data) { }
     * //  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^
     * ```
     * ```
     * (method_declaration
     *     (modifiers)?
     *     <type_parameters: (type_parameters)>?
     *     type: (_)
     *     name: (identifier)
     *     parameters: (formal_parameters [(formal_parameter) (spread_parameter)]*)
     *     (throws)?
     *     body: (block))
     * ```
     * @param {TreeSitterNode} node
     */
    visitMethodDecl(node) {
        // (A method implicitly has its own scope that doesn't line up with a CST block node).
        this.enterBlock(false);

        const children = ddsa.getChildren(node);
        const formalParamsIdx = findFieldIndex(children, 2, "parameters");
        const formalParams = children[formalParamsIdx];

        const formalParamsChildren = ddsa.getChildren(formalParams);
        for (const param of formalParamsChildren) {
            const paramChildren = ddsa.getChildren(param);

            if (param.cstType === "formal_parameter") {
                // (formal_parameter (modifiers)? type: (_) name: (identifier))
                const nameIdx = findFieldIndex(paramChildren, 1, "name");
                const name = paramChildren[nameIdx];
                this.markCurrentDefinition(name.text, name);
            } else if (param.cstType === "spread_parameter") {
                // (spread_parameter (type_identifier) (variable_declarator))
                const spreadParamChildren = ddsa.getChildren(param);
                for (const paramChild of spreadParamChildren) {
                    if (paramChild.cstType === "variable_declarator") {
                        // (variable_declarator name: (identifier) <value: (_)>?)
                        const varDeclChildren = ddsa.getChildren(paramChild);
                        const nameIdx = findFieldIndex(varDeclChildren, 0, "name");
                        const name = varDeclChildren[nameIdx];
                        this.markCurrentDefinition(name.text, name);
                    }
                }
            }
        }

        const bodyIdx = findFieldIndex(children, formalParamsIdx + 1, "body");
        const body = children[bodyIdx];
        this.visitBlockStmt(body);
    }

    /**
     * Visits a `switch_expression`.
     * ```java
     * //  Can semantically behave as a "statement"...
     * //  vvvvvvvvvvvvvvvvvvvvv
     *     switch (example_01) {
     *         case x:
     *             break;
     *         default:
     *             break;
     *     }
     * //  ^^^^^^^^^^^^^^^^^^^^^
     *
     * //  ...or as an "expression".
     * //                 vvvvvvvvvvvvvvvvvvvvv
     *     String value = switch (example_02) {
     *         case 123:
     *             yield "one two three";
     *         default:
     *             yield "some string";
     *     };
     * //  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
     * //                 vvvvvvvvvvvvvvvvvvvvv
     *     String value = switch (example_03) {
     *         case 123 -> "one two three";
     *         default -> "some string";
     *     };
     * //  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
     * ```
     * ```
     * (switch_expression condition: (parenthesized_expression) body: (switch_block))
     * ```
     *
     * @param {TreeSitterNode} node
     */
    visitSwitchExpr(node) {
        this.enterBlock(true);

        const children = ddsa.getChildren(node);
        ignoreMutatingField(/* "condition" */);

        const switchBlockIdx = findFieldIndex(children, 1, "body");
        const switchBlock = children[switchBlockIdx];

        const caseStatements = ddsa.getChildren(switchBlock);
        for (const caseStatement of caseStatements) {
            switch (caseStatement.cstType) {
                // (switch_block_statement_group (switch_label (_)) (_)*)
                case "switch_block_statement_group": {
                    const children = ddsa.getChildren(caseStatement);
                    // If there is only one child (`switch_label`), this is a "trivial" fall through case
                    // so we can easily handle it.
                    if (children.length === 1) {
                        break;
                    }
                    // [simplification]
                    // Otherwise, logic to more complex fall-through switch cases is omitted.
                    //
                    // For example:
                    // ```java
                    // int y = 10;
                    // switch (value) {
                    //     case 1234:
                    //         y = 20;
                    //     case 5678:
                    //         y = 40;
                    //         break;
                    //     default:
                    //         y = 60;
                    // }
                    // In the `case 1234:` branch, the end value for `y` is always `40`, however, we will treat it as `20`.
                    const switchLabel = children[0];
                    const branchSemantic = nodeTextEquals(switchLabel, "default") ? BRANCH_TYPE_ALTERNATIVE : BRANCH_TYPE_CONSEQUENT;
                    this.enterBranch(branchSemantic);
                    // Visit everything after the `switch_label`.
                    const exprStmts = children.slice(1);
                    this._visitExprStmtList(node, exprStmts);
                    this.exitBlock();
                    break;
                }
                // (switch_rule (switch_label (_)) (expression_statement))
                case "switch_rule": {
                    const children = ddsa.getChildren(caseStatement);
                    const switchLabel = children[0];
                    const branchSemantic = nodeTextEquals(switchLabel, "default") ? BRANCH_TYPE_ALTERNATIVE : BRANCH_TYPE_CONSEQUENT;
                    this.enterBranch(branchSemantic);
                    for (let i = 1; i < children.length; i++) {
                        const child = children[i];
                        // The sole `expression_statement` behaves like a `yield_statement`:
                        if (child.cstType === "expression_statement") {
                            // (NB: The first child cannot be a comment, so it is safe to manually index into this array)
                            const innerExpr = ddsa.getChildren(child)[0];
                            this.visit(innerExpr);
                            this.propagateLastTaint(node);
                            break;
                        }
                    }
                    this.exitBlock();
                    break;
                }
            }
        }
        this.exitBlock();
    }
    
    /**
     * Visits a `synchronized_statement`.
     * ```java
     *     Example01 obj = new Example01();
     *     synchronized (obj.field) { }
     * //  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^
     * ```
     * ```
     * (synchronized_statement (parenthesized_statement) body: (block))
     * ```
     * @param {TreeSitterNode} node
     */
    visitSynchronizedStmt(node) {
        const children = ddsa.getChildren(node);
        // TODO(JF): After scoped variable support: add (parenthesized_statement) to defs

        const bodyIdx = findFieldIndex(children, 1, "body");
        const body = children[bodyIdx];
        this.visitBlockStmt(body);
    }

    /**
     * Visits a `try_statement`.
     * ```java
     *     try { } catch (Exception example_01) { }
     * //  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
     *     try { } catch (Exception e) { } finally { }
     * //  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
     *     try { } finally { }
     * //  ^^^^^^^^^^^^^^^^^^^
     * ```
     * ```
     * (try_statement body: (block) [((catch_clause) (finally_clause)) (catch_clause) (finally_clause)])
     * ```
     * @param {TreeSitterNode} node
     */
    visitTryStmt(node) {
        const children = ddsa.getChildren(node);
        const tryBlockIdx = findFieldIndex(children, 0, "body");
        const tryBlock = children[tryBlockIdx];
        this.visitBlockStmt(tryBlock);

        const len = children.length;
        for (let i = tryBlockIdx + 1; i < len; i++) {
            const child = children[i];
            switch (child.cstType) {
                // (catch_clause (catch_formal_parameter) body: (block))
                case "catch_clause": {
                    const catchChildren = ddsa.getChildren(child);
                    const bodyIdx = findFieldIndex(catchChildren, 1, "body");
                    const body = catchChildren[bodyIdx];
                    this.visitBlockStmt(body);
                    break;
                }
                // (finally_clause (block))
                case "finally_clause": {
                    const finallyChildren = ddsa.getChildren(child);
                    for (const child of finallyChildren) {
                        if (child.cstType === "block") {
                            this.visitBlockStmt(child);
                            break;
                        }
                    }
                    break;
                }
                case "block_comment":
                case "line_comment":
                    break;
                default:
                    throw new Error("unreachable");
            }
        }
    }

    /**
     * Visits a `while_statement`.
     * ```java
     *     while (true) { }
     * //  ^^^^^^^^^^^^^^^^
     * ```
     * ```
     * (while_statement condition: (parenthesized_expression) body: (block))
     * ```
     * @param {TreeSitterNode} node
     */
    visitWhileStmt(node) {
        const children = ddsa.getChildren(node);
        ignoreMutatingField(/* "condition" */);

        const bodyIdx = findFieldIndex(children, 1, "body");
        const body = children[bodyIdx];
        this.visitBlockStmt(body);
    }

    ///////////////////////////////////////////////////////////////////////////
    // Internal Bookkeeping
    ///////////////////////////////////////////////////////////////////////////

    /**
     * Returns the definition of a variable at the given a stack height.
     * @param {string} identifier The variable name
     * @param {number} stackHeight The one-based height to begin variable resolution at.
     * @returns {VertexId | undefined}
     */
    resolveVariableAt(identifier, stackHeight) {
        if (stackHeight < 1 || stackHeight > this.context.scopeStack.length) {
            throw new Error(`height ${stackHeight} is out of bounds`);
        }
        for (let i = stackHeight - 1; i >= 0; i--) {
            const scope = this.context.scopeStack[i];
            const value = scope.getVariable(identifier);
            if (value !== undefined) {
                return value;
            }
        }
        return undefined;
    }

    /**
     * Takes a {@link TreeSitterNode} out of {@link TraversalContext} `lastTaintSource` (if it exists),
     * leaving `undefined` in its place.
     * @returns {TreeSitterNode | undefined}
     */
    takeLastTainted() {
        const last = this.context.lastTaintSource;
        this.context.lastTaintSource = undefined;
        return last;
    }

    /**
     * Marks the provided {@link TreeSitterNode} as the last tainted node.
     */
    markLastTainted(node) {
        this.context.lastTaintSource = node;
    }

    /**
     * Propagates taint from the {@link TraversalContext} `lastTaintSource` (if it exists) to the target node.
     * @param {TreeSitterNode} target
     */
    propagateLastTaint(target) {
        const lastSource = this.context.lastTaintSource;
        if (lastSource === undefined) {
            return;
        }
        // Ignore comments (putting this check here allows each visitor to not have to explicitly handle comments).
        if (isCommentNode(target)) {
            return;
        }
        this.graph.addTypedEdge(vertexId(target), vertexId(lastSource), EDGE_DEPENDENCE);
        this.context.lastTaintSource = target;
    }

    /**
     * Enters a new block scope.
     * @param {boolean} isConditional
     */
    enterBlock(isConditional) {
        this._enterBlockInner(isConditional, 0);
    }

    /**
     * Enters a new block scope that represents a branch within {@link ConditionalBlock}.
     * @param {BranchSemantic} branchSemantic
     */
    enterBranch(branchSemantic) {
        this._enterBlockInner(false, branchSemantic);
    }

    /**
     * Enters a new block scope.
     * @param {boolean} isConditional
     * @param {BranchSemantic} branchSemantic
     */
    _enterBlockInner(isConditional, branchSemantic) {
        if (this.currentBlock()?.isConditional) {
            this.context.conditionalAncestorBlocks += 1;
        }
        /** @type {ScopeBlock | ConditionalBlock} */
        let block;
        if (isConditional) {
            block = new ConditionalBlock();
        } else {
            block = new ScopeBlock();
        }
        block.branchSemantic = branchSemantic;
        this.context.scopeStack.push(block);
    }

    /**
     * Exits the current lexical scope, returning it.
     * @returns {ScopeBlock}
     */
    exitBlock() {
        /** @type {ScopeBlock} */
        const popped = this.context.scopeStack.pop();
        const current = this.currentBlock();

        // Exiting a conditional block means that this is a merge point:
        // Additionally, for each phi candidate, we now can determine if the branches represent exhaustive assignment.
        if (popped.isConditional) {
            /** @type {ConditionalBlock} */
            const poppedBlock = popped;
            if (poppedBlock.branchCount > 0 && poppedBlock.phiCandidates !== undefined) {
                // Create the phi nodes and reassign definitions.
                this._handleMergePoint(poppedBlock);
            }
            this.context.conditionalAncestorBlocks -= 1;
        } else {
            /** @type {ScopeBlock} */
            const poppedBlock = popped;
            // If this is a branch, perform the required accounting on the `currentBlock` phi candidates.
            if (poppedBlock.branchSemantic !== 0) {
                /** @type {ConditionalBlock} */
                const currentBlock = current;
                if (!currentBlock.isConditional) {
                    throw new Error("CFG branch block parent must be a conditional block");
                }
                currentBlock.branchCount += 1;

                if (poppedBlock.definitions !== undefined) {
                    if (currentBlock.phiCandidates === undefined) {
                        currentBlock.phiCandidates = new Map();
                    }
                    for (const [identifier, incomingValue] of poppedBlock.definitions.entries()) {
                        // [simplification]
                        // If there is no live definition of this variable, this could have been (and to simplify,
                        // we assume that this was) a local definition that was dropped upon exiting the just-popped scope.
                        if (this.resolveVariableAt(identifier, this.context.scopeStack.length) === undefined) {
                            continue;
                        }
                        /** @type {PhiCandidate} */
                        let candidate = currentBlock.phiCandidates.get(identifier);
                        if (candidate === undefined) {
                            candidate = { exhaustiveness: 0, operands: new Set() };
                            currentBlock.phiCandidates.set(identifier, candidate);
                        }
                        candidate.exhaustiveness |= poppedBlock.branchSemantic;
                        candidate.operands.add(incomingValue);
                    }
                }
            } else {
                // An immediate child of a conditional block must be a branch block. Because this isn't a branch,
                // `current` cannot be a conditional block (thus, it must be a normal scope block). However,
                // we may still have an ancestor (non-parent) conditional block. If so, we need to propagate
                // assignments up to the parent so that they can be processed as phi candidates when the
                // ancestor conditional block is exited.
                //
                // [simplification]
                // NOTE: as documented on `MethodFlow`, variable lexical scoping is not supported, so there is no checking
                // of whether these were only local assignments to variables that will be dropped.
                if (this.context.conditionalAncestorBlocks > 0 && poppedBlock.definitions !== undefined) {
                    for (const [identifier, vertexId] of poppedBlock.definitions) {
                        (/** @type {ScopeBlock} */ current)._markAssignmentInner(identifier, vertexId);
                    }
                }
            }
        }

        return popped;
    }

    /**
     * Returns a reference to the current scope block.
     * This is never `undefined` because `MethodFlow` should always have a balanced stack.
     * @returns {ScopeBlock | ConditionalBlock}
     */
    currentBlock() {
        return /** @type {ScopeBlock | ConditionalBlock} */ (this.context.scopeStack.at(-1));
    }

    /**
     * Marks the node as the current definition of a variable.
     *
     * [simplification]
     * Variable scoping is not supported. (See documentation on {@link MethodFlow}).
     *
     * Returns the previous assignment, if it exists.
     * @param {string} identifier
     * @param {Vertex} vertex
     * @returns {VertexId | undefined}
     */
    markCurrentDefinition(identifier, vertex) {
        /** @type {ScopeBlock | ConditionalBlock} */
        let selectedScope;

        // [simplification]
        // If in a conditional block, set the definition only for the current block instead of trying
        // to find its last-known latest definition. Without this simplification, if there are nested
        // conditional blocks with both assignments and variable shadowing, we'd need to maintain the
        // scope height of each conditional assignment in order to "reset" the state as we exit a scope.
        if (this.context.conditionalAncestorBlocks > 0 ) {
            selectedScope = this.currentBlock();
        } else {
            for (let i = this.context.scopeStack.length - 1; i >= 0; i--) {
                const scope = this.context.scopeStack[i];
                if (scope.getVariable(identifier) !== undefined) {
                    selectedScope = scope;
                    break;
                }
            }
            selectedScope = selectedScope ?? this.currentBlock();
        }
        return selectedScope.markAssignment(identifier, vertex);
    }

    /**
     * Reconciles assignments from all blocks within the provided conditional block by constructing phi nodes and
     * re-assigning the latest definition for each variable to that phi node.
     * @param {ConditionalBlock} block
     */
    _handleMergePoint(block) {
        // `phiCandidates` will be `undefined` if there were no assignments within the conditional block.
        if (block.phiCandidates === undefined) {
            return;
        }

        for (const [identifier, candidate] of block.phiCandidates.entries()) {
            const phiNode = this.graph.newPhiNode();
            const wasExhaustive = candidate.exhaustiveness === ALL_BRANCH_TYPES && candidate.operands.size === block.branchCount;

            // Construct a new phi node with operands that represent potential values this `identifier`
            // could have, depending on the control flow up to this point.
            //
            // For example, for the following code:
            // ```java
            // int y = 9;
            // if (condition) {
            //     y = 5;
            // }
            // System.out.println(y);
            // ```
            //
            // The control flow graph is the following:
            //
            //                         +----------+
            //                         |  y <- 9  | (y0)
            //                         +----------+
            //                              |
            //                              v
            //                      +----------------+    B: true
            //              +------ | if (condition) | ----------+
            //              |       +----------------+           |
            //              |                                   +--------+
            //     A: false |                                   | y <- 5 | (y1)
            //              |                                   +--------+
            //              |       +------------+               |
            //              +-----> | println(y) | <-------------+
            //                      +------------+
            //
            // This particular example demonstrates a non-exhaustive control flow construct, so
            // there are two categories of paths:
            if (!wasExhaustive) {
                // Path A:
                // ------
                // In the `condition == false` path, the variable mutation never happens. The first operand is
                // the last assigned definition of the `identifier` in reference to the current scope (in this case, y1).
                const currentDefinition = this.resolveVariableAt(identifier, this.context.scopeStack.length);
                // [simplification]
                // Don't handle the case where an assignment can't be matched with a corresponding previous assignment.
                // This can happen if:
                // * A variable outside the method is being assigned.
                // * The assignment was for a scope-local variable that was dropped when the scope was dropped.
                if (currentDefinition !== undefined) {
                    phiNode.appendOperand(currentDefinition);
                }
            }

            // Path B:
            // ------
            // In the `condition == true` path, the variable is mutated to equal the incoming value (y1). Here,
            // operands will be a set containing only `y1`.
            for (const operand of candidate.operands) {
                phiNode.appendOperand(operand);
            }
            // Thus, when the program reaches:
            //
            // ```java
            // System.out.println(y);
            // ```
            //
            // The value of `y` will be either `y0` or `y1`.
            // This mutual exclusion is encapsulated as a phi function, with an operand for each possibility:
            // y2 = phi(y0, y1)

            // Draw edges to operands and then reassign the current definition of `y` to this phi node (y2).
            for (const operand of phiNode.operands) {
                this.graph.addTypedEdge(vertexId(phiNode), operand, EDGE_DEPENDENCE);
            }

            // [simplification]
            // Variable scoping is not supported (see documentation on `MethodFlow`).
            // Thus, our current implementation always performs assignments as if the variable was defined
            // in the "current" scope. However, because separate branches often mutate variables in
            // an external scope, in order to more properly place the phi node within a scope without
            // implementing true variable scoping, we traverse down the stack to find the scope
            // with the most recent assignment to this variable.
            /** @type {ScopeBlock | ConditionalBlock} */
            let selectedScope;
            for (let i = this.context.scopeStack.length - 1; i >= 0; i--) {
                const scope = this.context.scopeStack[i];
                if (scope.getVariable(identifier) !== undefined) {
                    selectedScope = scope;
                    break;
                }
            }
            selectedScope = selectedScope ?? this.currentBlock();
            selectedScope.markAssignment(identifier, phiNode);
        }
    }
}

/**
 * As the CST is traversed, an implicit control flow graph (CFG) is constructed to simulate abstract states of the program.
 * At times, this requires a CST node visitor to know information from a CST parent or CST child. This context allows for
 * indirect data passing between recursive visitor function invocations.
 * @typedef TraversalContext
 *
 * @property {TreeSitterNode | undefined} lastTaintSource The last tainted expression node (if any).
 * This is used to propagate taint between nodes in the graph.
 * 
 * @property {Array<ScopeBlock | ConditionalBlock>} scopeStack A stack of blocks, which is used to implement
 * control flow scoping (and eventually variable scoping).
 *
 * @property {number} conditionalAncestorBlocks
 */

/**
 * @typedef {number & { _brand: "BranchSemantic" }} BranchSemantic
 * A flag to indicate the semantic of a (simple) branching control flow construct. This is used to determine whether
 * a variable has been assigned exhaustively or not.
 *
 * NB: this is an unconventional, yet very simple technique which lets us determine branch exhaustiveness at
 * a control flow merge point without having to explicitly construct a CFG and then do DFS to determine exhaustiveness.
 * 1. Within each CFG conditional block visitor function, we annotate whether the visit represents a semantic
 * {@link BRANCH_CONSEQUENT|consequent} or an {@link BRANCH_ALTERNATIVE|alternative}.
 * 2. Upon phi node creation, if an identifier was assigned a value in 1) a consequent, 2) an alternative, and 3) every branch,
 * it has been assigned exhaustively.
 *
 * Possible values:
 * * {@link BRANCH_TYPE_CONSEQUENT}
 * * {@link BRANCH_TYPE_ALTERNATIVE}
 */

/**
 * A flag for an assignment that occurs semantically within the "consequent" of a conditional.
 * @type {BranchSemantic}
 */
const BRANCH_TYPE_CONSEQUENT = 0b01;
/**
 * A flag for an assignment that occurs semantically within the "alternative" of a conditional.
 * @type {BranchSemantic}
 */
const BRANCH_TYPE_ALTERNATIVE = 0b10;

/**
 * A value indicating that both the {@link BRANCH_TYPE_CONSEQUENT} and the {@link BRANCH_TYPE_ALTERNATIVE}
 * flags have been set.
 *
 * @type {BranchSemantic}
 */
const ALL_BRANCH_TYPES = BRANCH_TYPE_CONSEQUENT | BRANCH_TYPE_ALTERNATIVE;

/**
 * @typedef PhiCandidate
 * @property {BranchSemantic} exhaustiveness
 * @property {Set<VertexId>} operands
 */

/**
 * A map that collects assignments across mutually exclusive conditional blocks. These assignments
 * need to be reconciled (with a phi node) upon reaching a merge point in the control flow graph.
 * @typedef {Map<string, PhiCandidate>} PhiCandidates
 */

 /**
 * Returns `true` if the node's text equals the provided `text`.
 * For better performance, this function should always be used instead of a vanilla equality
 * check (`===` or `==`).
 *
 * @param {TreeSitterNode} node
 * @param {string} text
 * @returns {boolean}
 */
function nodeTextEquals(node, text) {
    // (The reason for this as a distinct function instead of a vanilla JavaScript equality check
    // is that by cheaply verifying the length of the node's CST span matches the provided `text`,
    // we can sometimes avoid a relatively expensive call into Rust and a v8 string allocation).
    if (node._startLine === node._endLine) {
        const nodeTextLength = node._endCol - node._startCol;
        if (nodeTextLength !== text.length) {
            return false;
        }
    }
    return node.text === text;
}

/**
 * Returns the index of the first node with a matching `fieldName`, or `-1` if it doesn't exist.
 *
 * @param {Array<TreeSitterFieldChildNode>} children
 * @param {number} start The index of `children` to start iterating from.
 * @param {string} fieldName The tree-sitter field name of the child.
 * @returns number
 */
function findFieldIndex(children, start, fieldName) {
    const len = children.length;
    for (let i = start; i < len; i++) {
        if (children[i].fieldName === fieldName) {
            return i;
        }
    }
    return -1;
}

/**
 * Returns `true` if the CST node is semantically a comment, or `false` if not.
 * @param {TreeSitterNode | TreeSitterFieldChildNode} node
 */
function isCommentNode(node) {
    switch (node.cstType) {
        case "block_comment":
        case "line_comment":
            return true;
        default:
            return false;
    }
}

/**
 * @typedef {0 | 1} BinExprOp
 * An integer representing the operator of a binary expression. Possible values:
 * * {@link BIN_EXPR_OP_IGNORED}
 * * {@link BIN_EXPR_OP_ADD}
 */

/** @type {0} */
export const BIN_EXPR_OP_IGNORED = 0;
/** @type {1} */
export const BIN_EXPR_OP_ADD = 1;

/**
 * A noop function intended for documentation:
 *
 * Technically a mutation can happen in this node via a function call, but we ignore it for simplicity because
 * we haven't implemented variable scopes.
 *
 * NB: While this function does not expect an argument to avoid runtime string allocation, the argument list
 * should contain a comment describing the field name of a node for documentation purposes, e.g.
 * ```js
 * ignoreMutatingField(
 *     // "exampleName"
 * );
 * ```
 */
function ignoreMutatingField() {
    // noop
}

/**
 * A block that is a lexical scope.
 */
class ScopeBlock {
    constructor() {
        /**
         * Whether this block scope is conditional in the CFG or not.
         * @type {boolean}
         */
        this.isConditional = false;

        /**
         * If this block represents a branch within a CFG conditional block, this is the "semantic"
         * of that branch.
         * @type {BranchSemantic}
         */
        this.branchSemantic = 0;

        /**
         * A map from a variable name to its current definition within the scope. No history is preserved when a re-assignment is made.
         * @type {VariableDefs | undefined}
         *
         * NB: When variable scoping is supported, this will be an array of maps in order to support re-assignments
         *     of variables from external scopes.
         */
        this.definitions = undefined;
    }

    /**
     * Marks the node as the current definition of a variable within this scope.
     * Returns the previous assignment, if it exists.
     * @param {string} identifier
     * @param {Vertex} vertex
     * @returns {VertexId | undefined}
     */
    markAssignment(identifier, vertex) {
        const previousValue = this.definitions?.get(identifier);
        this._markAssignmentInner(identifier, vertexId(vertex));
        return previousValue;
    }

    /**
     * Marks the vertex id as the current definition of a variable within this scope.
     * @param {string} identifier
     * @param {VertexId} vertexId
     */
    _markAssignmentInner(identifier, vertexId) {
        // Lazily instantiate the map
        if (this.definitions === undefined) {
            this.definitions = new Map();
        }

        // [simplification]
        // Variable scoping is not supported, so this always sets the assignment directly on this scope.
        // When variable scoping is supported, `markReassign` will need to accept a `height` parameter
        // and perform the re-assignment at the provided height.
        this.definitions.set(identifier, vertexId);
    }

    /**
     * Returns the latest assignment of variable, if it exists.
     * @param {string} identifier
     * @returns {VertexId | undefined}
     */
    getVariable(identifier) {
        return this.definitions?.get(identifier);
    }
}

/**
 * A map from a string identifier to its {@link VertexId} location where it was last assigned a value.
 * @typedef {Map<string, VertexId>} VariableDefs
 */


/**
 * A CFG conditional block.
 *
 * (NOTE: This is additionally a lexical scope, and thus it behaves the same as @link @{ScopeBlock}
 * when it comes to scope).
 */
class ConditionalBlock extends ScopeBlock {
    constructor() {
        super();
        this.isConditional = true;

        /**
         * The number of blocks (representing branches of a conditional block) that are direct children.
         *
         * For example:
         * ```java
         * if (condition) {
         *     y = 10;
         * }
         * // branchCount === 1
         *
         * if (condition) {
         *     y = 10;
         * } else if (condition2) {
         *     // no-op
         * } else {
         *     y = 30;
         * }
         * // branchCount === 3;
         * ```
         * @type {number}
         */
        this.branchCount = 0;

        /**
         * The state of all conditional block mutations within this block's immediate scope. See {@link PhiCandidates}
         * for additional documentation.
         * @type {PhiCandidates | undefined}
         */
        this.phiCandidates = undefined;
    }
}
