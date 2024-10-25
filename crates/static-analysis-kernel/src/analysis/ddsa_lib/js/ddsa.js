// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

import { _findTaintFlows, transpose, vertexId } from "ext:ddsa_lib/flow/graph";
import { MethodFlow } from "ext:ddsa_lib/flow/java";
import { SEALED_EMPTY_ARRAY } from "ext:ddsa_lib/utility";
import { TreeSitterFieldChildNode } from "ext:ddsa_lib/ts_node";

const { op_digraph_adjacency_list_to_dot, op_ts_node_named_children, op_ts_node_parent } = Deno.core.ops;

/**
 * The main entrypoint to the ddsa JavaScript runtime's API.
 */
export class DDSA {
    constructor() {}

    /**
     * Fetches and returns the named children of the provided node, if they exist.
     * If no named children exist, an empty array will be returned. Named children are tree-sitter
     * nodes that aren't anonymous (i.e. they have a `cstType`).
     * @param {TreeSitterNode | TreeSitterFieldChildNode} node
     * @returns {Array<TreeSitterNode | TreeSitterFieldChildNode>}
     */
    getChildren(node) {
        const childTuples = op_ts_node_named_children(node.id);
        if (childTuples === null) {
            return SEALED_EMPTY_ARRAY;
        }
        const children = [];
        const len = childTuples.length;
        for (let i = 0; i < len; i += 2) {
            const node = globalThis.__RUST_BRIDGE__ts_node.get(childTuples[i]);
            const fieldId = childTuples[i + 1];
            // Only allocate a new `TreeSitterFieldChildNode` if the node has a field name (indicated by a non-zero fieldId).
            if (fieldId > 0) {
                children.push(new TreeSitterFieldChildNode(node, fieldId));
            } else {
                children.push(node);
            }
        }
        return children;
    }

    /**
     * Fetches and returns the provided node's parent in the tree-sitter tree.
     * If the node is the root node of the tree, `undefined` will be returned.
     * @param {TreeSitterNode | TreeSitterFieldChildNode} node
     * @returns {TreeSitterNode | undefined}
     */
    getParent(node) {
        const parentId = op_ts_node_parent(node.id);
        if (parentId === null) {
            return undefined;
        }
        return globalThis.__RUST_BRIDGE__ts_node.get(parentId);
    }

    /**
     * Returns a backwards flow analysis: a list of `TaintFlow` containing sources of the provided `sinkNode`.
     * @param {TreeSitterNode} sinkNode
     * @returns {Array<TaintFlow>}
     */
    getTaintSources(sinkNode) {
        // [simplification]: No caching is currently performed.
        const containingMethod = MethodFlow.findContainingMethod(sinkNode);
        if (containingMethod === undefined) {
            return SEALED_EMPTY_ARRAY;
        }
        const methodFlow = new MethodFlow(containingMethod);
        return _findTaintFlows(methodFlow.graph.adjacencyList, vertexId(sinkNode), false);
    }

    /**
     * Returns a **heuristic** forward flow analysis: a list of `TaintFlow` containing sinks for the provided `sourceNode`.
     *
     * # Limitations
     * These flows should only be used heuristically. They should not be relied on to be fundamentally accurate,
     * as they are generated from a simple but imprecise methodology:
     *
     * The initial flow analysis via {@link MethodFlow} traverses a CST and simulates an abstract program state (roughly
     * simulating a CFG) to output a (backwards) flow graph (sink to source).
     *
     * This function returns a heuristic forwards flow analysis by physically transposing the backwards flow graph.
     * This is inherently imprecise because it is operating on an implied CFG (not an actual one), so the ultimate
     * predecessor information could be incorrect.
     *
     * {@link DDSA.getTaintSources} will provide a more accurate (albeit backwards) analysis.
     *
     * @param {TreeSitterNode} sourceNode
     * @returns {Array<TaintFlow>}
     */
    getTaintSinks(sourceNode) {
        // [simplification]: No caching is currently performed on either the initial
        // graph or its transposition.
        const containingMethod = MethodFlow.findContainingMethod(sourceNode);
        if (containingMethod === undefined) {
            return SEALED_EMPTY_ARRAY;
        }
        const methodFlow = new MethodFlow(containingMethod);

        // See this function's documentation for why this is simple but imprecise.
        const transposed = transpose(methodFlow.graph.adjacencyList);
        ////////

        return _findTaintFlows(transposed, vertexId(sourceNode), true);
    }
}

/**
 * The entrypoint to the private (unpublished) API of the ddsa JavaScript runtime.
 * This API has no guarantee of stability.
 */
export class DDSAPrivate {
    /**
     * Converts a {@link Digraph} to its canonical DOT form with the provided graph name.
     * @param {Digraph} graph
     * @param {string} name
     *
     * @returns {string}
     */
    graphToDOT(graph, name) {
        return op_digraph_adjacency_list_to_dot(graph.adjacencyList, name) ?? "";
    }

    /**
     * Generates a {@link Digraph} from CST node, returning `undefined` if the node is not
     * a "method_declaration" node.
     *
     * NOTE: This method assumes it is running in a Java context.
     *
     * @param {TreeSitterNode}
     * @returns {Digraph | undefined}
     */
    generateJavaFlowGraph(node) {
        if (node?.cstType !== "method_declaration") {
            return undefined;
        }
        const methodFlow = new MethodFlow(node);
        return methodFlow.graph;
    }
}
