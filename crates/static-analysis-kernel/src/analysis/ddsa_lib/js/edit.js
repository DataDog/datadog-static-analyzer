// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

/**
 * An object containing metadata to perform a transformation of a point range within a text.
 */
export class Edit {
    /**
     * @param {number} startLine
     * @param {number} startCol
     * @param {number | undefined} endLine
     * @param {number | undefined} endCol
     * @param {EditKind} kind
     * @param {string | undefined} content
     */
    constructor(startLine, startCol, endLine, endCol, kind, content) {
        /**
         * The line number of the start of this edit.
         * @type {number}
         * @readonly
         */
        this.startLine = startLine;
        /**
         * The column number of the start of this edit.
         * @type {number}
         * @readonly
         */
        this.startCol = startCol;
        /**
         * The line number of the end of this edit. This will be `undefined` for `EditKind` "ADD".
         * @type {number | undefined}
         * @readonly
         */
        this.endLine = endLine;
        /**
         * The column number of the end of this edit. This will be `undefined` for `EditKind` "ADD".
         * @type {number | undefined}
         * @readonly
         */
        this.endCol = endCol;
        /**
         * @type {EditKind}
         * @readonly
         */
        this.kind = kind;
        /**
         * String content associated with this edit. This will be `undefined` for `EditKind` "DELETE".
         * @type {string | undefined}
         * @readonly
         */
        this.content = content;
    }

    /**
     * Creates a new edit with `EditKind` "ADD".
     * @param {number} startLine
     * @param {number} startCol
     * @param {string} content
     * @returns {Edit}
     */
    static newAdd(startLine, startCol, content) {
        return new Edit(startLine, startCol, undefined, undefined, "ADD", content);
    }

    /**
     * Creates a new edit with `EditKind` "REMOVE".
     * @param {number} startLine
     * @param {number} startCol
     * @param {number} endLine
     * @param {number} endCol
     * @returns {Edit}
     */
    static newRemove(startLine, startCol, endLine, endCol) {
        return new Edit(startLine, startCol, endLine, endCol, "REMOVE", undefined);
    }

    /**
     * Creates a new edit with `EditKind` "UPDATE".
     * @param {number} start_line
     * @param {number} start_col
     * @param {number} end_line
     * @param {number} end_col
     * @param {string} content The string to insert.
     * @returns {Edit}
     */
    static newUpdate(start_line, start_col, end_line, end_col, content) {
        return new Edit(start_line, start_col, end_line, end_col, "UPDATE", content);
    }
}

/**
 * @typedef { "ADD" | "REMOVE" | "UPDATE"} EditKind
 */
