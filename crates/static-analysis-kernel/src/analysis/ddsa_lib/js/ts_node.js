// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

import { op_ts_node_text } from "ext:core/ops";

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
            if (opResult === null) {
                // This branch is only accessible if this node's `id` is mutated such that a non-existent id
                // is passed into the op. In this case, return undefined.
                return undefined;
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
        return globalThis.__RUST_BRIDGE__context.tsLangCtx.nodeType.get(this._typeId) ?? "";
    }

    /**
     * A getter to return the named children of this tree-sitter node.
     * NOTE: This is deprecated, because it is a compatibility layer to support the stella API.
     * Do not rely on this, as it will be removed.
     *
     * @returns {Array<TreeSitterNode | TreeSitterFieldChildNode>}
     * @deprecated
     */
    get children() {
        return globalThis.ddsa.getChildren(this);
    }

    /**
     * A getter to return the string version of this node's type.
     * NOTE: This is deprecated, because it is a compatibility layer to support the stella API.
     * Do not rely on this, as it will be removed.
     *
     * @returns {string}
     * @deprecated
     */
    get astType() {
        return this.type;
    }
}

/**
 * The non-zero tree-sitter u16 field id for a child node in relation to a parent.
 * @typedef {number} FieldId
 */

/**
 * An object with the same interface as a {@link TreeSitterNode} that is the child of another node, and
 * additionally is tagged with a field name.
 * It does not mutate the `TreeSitterNode` that it wraps.
 *
 * @extends TreeSitterNode
 */
export class TreeSitterFieldChildNode {
    static [Symbol.hasInstance](instance) {
        // Because we set the prototype to the wrapped object, we lose the ability to call instanceof on `TreeSitterFieldChildNode`.
        // To implement it, we use the fact `TreeSitterFieldChildNode` uniquely has `_fieldId`.
        return instance instanceof TreeSitterNode && instance._fieldId !== undefined;
    }

    /**
     * @param {TreeSitterNode} tsNode The `TreeSitterNode` that will be wrapped.
     * @param {number} fieldId The field id of this child node.
     */
    constructor(tsNode, fieldId) {
        /**
         * The field id of this child node.
         * @type {FieldId}
         * @private
         * */
        this._fieldId = fieldId;

        /**
         * The field name associated with this child.
         * @type {string}
         * @readonly
         */
        // NOTE: We need to use `Object.defineProperty` so we can assign the property to this specific instance.
        // We can't use the `get` keyword, like:
        //
        // class TreeSitterFieldChildNode {
        //     get fieldName() { /* ... */ }
        // }
        //
        // because `fieldName` would then be assigned to the prototype, not the instance. That wouldn't work for us because
        // at the end of this constructor, we assign the prototype to the wrapped `TreeSitterNode`.
        Object.defineProperty(this, "fieldName", {
            get() {
                // Note: This will only return `undefined` if the `_fieldId` field is mutated. Because this is an unsupported
                // edge case, it's excluded from the type signature for clarity.
                return globalThis.__RUST_BRIDGE__context.tsLangCtx.field.get(this._fieldId);
            },
            enumerable: false,
            configurable: false,
        });

        // (Note: The use of `?? {}` is only because the Rust unit tests inspect the instance by invoking the constructor with no params)
        Object.setPrototypeOf(this, tsNode ?? {});
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
