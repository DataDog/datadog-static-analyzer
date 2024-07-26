// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

import { SEALED_EMPTY_ARRAY } from "ext:ddsa_lib/utility";
import { TreeSitterFieldChildNode } from "ext:ddsa_lib/ts_node";

import { op_ts_node_named_children } from "ext:core/ops";

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
}
