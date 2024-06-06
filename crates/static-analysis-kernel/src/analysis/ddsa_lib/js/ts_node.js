// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

const { op_ts_node_text } = Deno.core.ops;

/**
 * A non-zero integer assigned by the Rust static-analysis-kernel.
 *
 * This is not stable across analyses,
 * @typedef {number} NodeId
 */

/**
 * The tree-sitter u16 `TSSymbol`, specific to a tree-sitter Language.
 * @typedef {number} NodeTypeId
 */

/**
 * An object representing a node within a `tree-sitter Tree, as well as functions to access metadata about
 * both itself and its relationship to its context.
 */
export class TreeSitterNode {
    /**
     * @param {NodeId} id
     * @param {number} startLine
     * @param {number} startCol
     * @param {number} endLine
     * @param {number} endCol
     * @param {NodeTypeId} nodeTypeId
     */
    constructor(id, startLine, startCol, endLine, endCol, nodeTypeId) {
        /**
         * The id of this node, assigned by the Rust static analysis kernel.
         * @type {NodeId}
         * @private
         * */
        this.id = id;
        /** @type {number} */
        this.startLine = startLine;
        /** @type {number} */
        this.startCol = startCol;
        /** @type {number} */
        this.endLine = endLine;
        /** @type {number} */
        this.endCol = endCol;
        /** @type {NodeTypeId} */
        this._typeId = nodeTypeId;
        /**
         * A lazily-allocated string of the text that this node spans. This will only be stored if the text
         * is requested via the {@link TreeSitterNode.text} getter.
         * @type {string | undefined}
         * @private
         */
        this.__js_cachedText = undefined;
    }

    /**
     * A getter to return the text that this `TreeSitterNode` spans.
     * @returns {string}
     *
     * @remarks
     * This lazily makes a call to Rust to retrieve the node's text. Subsequent calls to this getter will
     * return the cached value.
     */
    get text() {
        if (this.__js_cachedText === undefined) {
            const opResult = op_ts_node_text(this.id);
            if (opResult === undefined) {
                // If there was a serialization error, default to an empty string.
                this.__js_cachedText = "";
            } else {
                this.__js_cachedText = opResult;
            }
        }
        return this.__js_cachedText;
    }

    /**
     * A getter to return the string version of this node's type.
     * @returns {string}
     *
     * @example
     * ```javascript
     * "function_declaration"
     * ```
     */
    get type() {
        // Note: the map lookup should only return undefined if either `this._typeId` or the symbol map were mutated.
        // Although that should never happen, we handle it by returning an empty string.
        // return globalThis.__RUST_BRIDGE__ts_symbol_lookup.get(this._typeId) ?? "";
        return "unimplemented"; // (The above line will be uncommented when the TsSymbol bridge is enabled in the runtime)
    }
}
