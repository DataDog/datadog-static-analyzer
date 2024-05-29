// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

/**
 * A static analysis violation to be reported to the Rust static analysis kernel.
 */
export class Violation {
    /**
     * @param {number} startLine
     * @param {number} startCol
     * @param {number} endLine
     * @param {number} endCol
     * @param {string} message
     */
    constructor(startLine, startCol, endLine, endCol, message) {
        /**
         * The line number of the start of this violation's text.
         * @type {number}
         * @readonly
         */
        this.startLine = startLine;
        /**
         * The column number of the start of this violation's text.
         * @type {number}
         * @readonly
         */
        this.startCol = startCol;
        /**
         * The line number of the end of this violation's text.
         * @type {number}
         * @readonly
         */
        this.endLine = endLine;
        /**
         * The column number of the end of this violation's text.
         * @type {number}
         * @readonly
         */
        this.endCol = endCol;
        /**
         * A human-friendly message describing the nature of the violation.
         * @type {string}
         * @readonly
         */
        this.message = message;
        /**
         * A list of `Fix` associated with this Violation.
         * @type {Array<Fix> | undefined}
         * */
        this.fixes = undefined;
    }

    /**
     * @param {Fix} fix
     * @returns {Violation}
     * Adds a fix to this violation and returns `this`.
     */
    addFix(fix) {
        if (this.fixes === undefined) {
            this.fixes = [];
        }
        this.fixes.push(fix);
        return this;
    }

    /**
     * Creates a new `Violation`.
     *
     * @param {number} startLine
     * @param {number} startCol
     * @param {number} endLine
     * @param {number} endCol
     * @param {string} message
     * @returns {Violation}
     *
     * @remarks
     * This is a convenience function to allow creation of a `Violation` without using the class constructor.
     * It is functionally equivalent to calling `new Violation(...)`.
     */
    static new(startLine, startCol, endLine, endCol, message) {
        return new Violation(startLine, startCol, endLine, endCol, message);
    }
}
