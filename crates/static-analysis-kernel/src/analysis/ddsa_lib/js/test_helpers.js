// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

/**
 * Throws an error if `value` is not `true`.
 * @param {boolean} value
 * @param {string} message
 */
export function assert(value, message) {
    if (!value) {
        throw new Error(message);
    }
}

/**
 * Returns the {@link TreeSitterNode} with the given id, if it exists.
 * @param {NodeId} nid
 * @returns {TreeSitterNode | undefined}
 */
export function getNode(nid) {
    return globalThis.__RUST_BRIDGE__ts_node.get(nid);
}
