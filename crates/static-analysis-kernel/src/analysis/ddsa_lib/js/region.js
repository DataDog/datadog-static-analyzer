// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

/**
 * A contiguous portion of a file.
 */
export class CodeRegion {
    /**
     * @param {number} startLine
     * @param {number} startCol
     * @param {number} endLine
     * @param {number} endCol
     */
    constructor(startLine, startCol, endLine, endCol) {
        /**
         * A positive integer equal to the line number containing the first character of this region.
         * @type {number}
         * @readonly
         */
        this.startLine = startLine;
        /**
         * A positive integer equal to the column number of the first character of this region.
         * @type {number}
         * @readonly
         */
        this.startCol = startCol;
        /**
         * A positive integer equal to the line number containing the last character of this region.
         * @type {number}
         * @readonly
         */
        this.endLine = endLine;
        /**
         * A positive integer whose value is one greater than column number of the last character in this region.
         * @type {number}
         * @readonly
         */
        this.endCol = endCol;
    }
}
