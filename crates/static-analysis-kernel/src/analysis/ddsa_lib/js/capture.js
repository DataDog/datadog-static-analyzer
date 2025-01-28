// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

/**
 * @typedef {SingleCapture | MultiCapture} NamedCapture
 * Note that both interfaces use `string` for `name` because these objects are only created directly
 * via the v8 API, so we can guarantee that these will be implemented as interned strings.
 */

/**
 * @typedef {Object} SingleCapture
 * @property {string} name The name of the capture.
 * @property {NodeId} nodeId The node that was captured.
 *
 * Example tree-sitter query:
 * ```
 * (identifier) @capture_name
 * ```
 */

/**
 * @typedef {Object} MultiCapture
 * @property {string} name The name of the capture.
 * @property {Array<NodeId>} nodeIds The nodes that were captured.
 *
 * Example tree-sitter query:
 * ```
 * (identifier) @duplicate_name
 * (number) @duplicate_name
 * ```
 */
