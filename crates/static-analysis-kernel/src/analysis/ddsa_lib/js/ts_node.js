// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

import { SEALED_EMPTY_ARRAY } from "ext:ddsa_lib/utility";

const { op_ts_node_named_children, op_ts_node_text } = Deno.core.ops;

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
 * A specific point (1-based line number, 1-based column number) within a source text.
 * @typedef {Object} Position
 * @property {number} line
 * @property {number} col
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
        /**
         * @type {number}
         * @private
         */
        this._startLine = startLine;
        /**
         * @type {number}
         * @private
         */
        this._startCol = startCol;
        /**
         * @type {number}
         * @private
         */
        this._endLine = endLine;
        /**
         * @type {number}
         * @private
         */
        this._endCol = endCol;
        /** @type {NodeTypeId} */
        this._typeId = nodeTypeId;
        /**
         * A lazily-allocated start {@link Position}, created and/or returned when requested via the {@link TreeSitterNode.start} getter.
         * @type {Position | undefined}
         * @private
         */
        this._cachedStart = undefined;
        /**
         * A lazily-allocated end {@link Position}, created and/or returned when requested via the {@link TreeSitterNode.end} getter.
         * @type {Position | undefined}
         * @private
         */
        this._cachedEnd = undefined;
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
     * A getter to return the start {@link Position} of this node.
     * Note that this getter returns a cached object -- the caller should not mutate it.
     * @returns {Position}
     */
    get start() {
        if (this._cachedStart === undefined) {
            this._cachedStart = buildPosition(this._startLine, this._startCol);
        }
        return this._cachedStart;
    }

    /**
     * A getter to return the end {@link Position} of this node.
     * Note that this getter returns a cached object -- the caller should not mutate it.
     * @returns {Position}
     */
    get end() {
        if (this._cachedEnd === undefined) {
            this._cachedEnd = buildPosition(this._endLine, this._endCol);
        }
        return this._cachedEnd;
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
        return globalThis.__RUST_BRIDGE__ts_symbol_lookup.get(this._typeId) ?? "";
    }

    /**
     * A getter to return the named children of this tree-sitter node.
     * NOTE: This is deprecated, because it is a compatibility layer to support the stella API.
     * Do not rely on this, as it will be removed.
     *
     * @returns {Array<TreeSitterNode>}
     * @deprecated
     */
    get children() {
        const childIds = op_ts_node_named_children(this.id);
        if (childIds === undefined) {
            return SEALED_EMPTY_ARRAY;
        }
        const children = [];
        for (const childId of childIds) {
            children.push(globalThis.__RUST_BRIDGE__ts_node.get(childId))
        }
        return children;
    }
}

/**
 * Creates a new {@link Position} from a line and row number.
 * @param {number} lineNumber The 1-based line number
 * @param {number} columnNumber The 1-based column number
 * @returns {Position}
 */
function buildPosition(lineNumber, columnNumber) {
    return {
        line: lineNumber,
        col: columnNumber
    };
}
