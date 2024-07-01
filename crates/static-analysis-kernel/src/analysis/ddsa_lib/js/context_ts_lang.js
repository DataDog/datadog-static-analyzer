// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

/**
 * @typedef {Map<string | number, string | number>} MetadataMap
 * A map and reverse mapping for metadata about a specific facet of a tree-sitter language:
 * All entries will either be:
 * * `number` (u16) -> `string`,
 * * `string` -> `number` (u16)
 */

/**
 * Metadata related to a tree-sitter Language.
 */
export class TsLanguageContext {
    constructor() {
        /**
         * @type {MetadataMap} Metadata for the language's "node kind"s.
         * @readonly
         * @internal
         *
         * @remarks
         * This is initialized as an empty Map to give v8 a hint about the object shape. It ends
         * up being replaced by a v8::Global map.
         */
        this.nodeType = new Map();
        /**
         * @type {MetadataMap} Metadata for the language's "field"s.
         * @readonly
         * @internal
         *
         * @remarks
         * This is initialized as an empty Map to give v8 a hint about the object shape. It ends
         * up being replaced by a v8::Global map.
         */
        this.field = new Map();
    }
}
