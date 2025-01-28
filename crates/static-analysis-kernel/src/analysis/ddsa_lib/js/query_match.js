// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

/**
 * A collection of named captures that represents an individual "match" from a tree-sitter query.
 */
export class QueryMatch {
    /**
     * @param {Array<NamedCapture> | undefined} captures
     */
    constructor(captures) {
        /**
         * @type {Array<NamedCapture> | undefined}
         * @readonly
         * @private
         */
        this._captures = captures;
    }

    /**
     * Returns the node with the given capture name, following semantics from {@link QueryMatch._getId}
     * @param {string} name
     * @returns {TreeSitterNode | undefined}
     */
    get(name) {
        const nodeId = this._getId(name);
        if (nodeId === undefined) {
            return undefined;
        }
        // Note: the Rust bridge guarantees that this map element will be present (assuming `_captures` was not mutated).
        return globalThis.__RUST_BRIDGE__ts_node.get(nodeId);
    }

    /**
     * Returns the id of the node with the given capture name. If there are multiple matching captures,
     * only the last will be returned, and the rest will be silently ignored.
     * @param {string} name
     * @returns {NodeId | undefined}
     *
     * @remarks
     * This is implemented as `O(N)` iteration instead of `O(1)` lookup because the expected number of
     * capture names is small (e.g. < 10).
     */
    _getId(name) {
        const len = this._captures?.length ?? 0;
        for (let i = 0; i < len; i++) {
            const item = this._captures[i];
            if (item.name === name) {
                if (item.nodeIds !== undefined) {
                    // By convention, we return the last match if there are multiple.
                    // This is guaranteed to be at least length 1, so this won't underflow.
                    return item.nodeIds[item.nodeIds.length - 1];
                } else {
                    return item.nodeId;
                }
            }
        }
        return undefined;
    }

    /**
     * Returns an array of the nodes with the given capture name, following semantics from {@link QueryMatch._getManyIds}
     * @param {string} name
     * @returns {Array<TreeSitterNode> | undefined}
     */
    getMany(name) {
        const nodeIds = this._getManyIds(name);
        if (nodeIds === undefined) {
            return undefined;
        }
        const nodes = [];
        const len = nodeIds.length;
        for (let i = 0; i < len; i++) {
            const nodeId = nodeIds[i];
            // Note: the Rust bridge guarantees that this map element will be present (assuming `_captures` was not mutated).
            const node = globalThis.__RUST_BRIDGE__ts_node.get(nodeId);
            nodes.push(node);
        }
        return nodes;
    }

    /**
     * Returns an array of the ids of nodes with the given capture name.
     * If this is called on a capture that is a `SingleCapture` instead of a `MultiCapture`, the capture
     * will be turned in an array as the sole element.
     * @param {string} name
     * @returns {Array<NodeId> | undefined}
     *
     * @remarks
     * This is implemented as `O(N)` iteration instead of `O(1)` lookup because the expected number of
     * capture names is small (e.g. < 10).
     */
    _getManyIds(name) {
        const len = this._captures?.length ?? 0;
        for (let i = 0; i < len; i++) {
            const item = this._captures[i];
            if (item.name === name) {
                if (item.nodeIds !== undefined) {
                    return item.nodeIds;
                } else {
                    return [item.nodeId];
                }
            }
        }
        return undefined;
    }
}
