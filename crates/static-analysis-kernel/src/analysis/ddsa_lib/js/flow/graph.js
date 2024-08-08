// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

/**
 * A directed graph.
 */
export class Digraph {
    constructor() {
        /**
         * The adjacency list representation of this digraph.
         * @type {AdjacencyList}
         */
        this.adjacencyList = new Map();
    }

    /**
     * Adds a typed, directed edge from a source {@link VertexId} to a target `VertexId`.
     * @param {VertexId} from
     * @param {VertexId} to
     * @param {EdgeKind} kind
     */
    addTypedEdge(from, to, kind) {
        _addTypedEdge(this.adjacencyList, from, to, kind);
    }
}

/**
 * @typedef {number & { _brand: "Edge" }} Edge
 * A typed edge in a {@link Digraph} storing a target {@link VertexId} and an {@link EdgeKind}.
 *
 * Internally, this is a bit-packed integer:
 * ```text
 *            49 bits           4 bits
 * |---------------------------|----|
 *         targetVertexId       kind
 * ```
 *
 * This serialization format stores the same information as an object with the shape:
 * ```js
 * const edge = {
 *     targetVertexId: targetVertexId,
 *     kind: kind,
 * };
 * ```
 */

/**
 * @typedef {Map<VertexId, Array<Edge>>} AdjacencyList
 * An adjacency list represented as a Map.
 */

/**
 * @typedef {TreeSitterNode} Vertex
 * A vertex in a {@link Digraph}.
 */

/**
 * @typedef {number & { _brand: "VertexId" }} VertexId
 * An id of {@link Vertex}.
 */

/**
 * Adds a typed, directed edge from a source {@link VertexId} to a target `VertexId`.
 * @param {AdjacencyList} adjacencyList
 * @param {VertexId} from
 * @param {VertexId} to
 * @param {EdgeKind} kind
 */
function _addTypedEdge(adjacencyList, from, to, kind) {
    if (from === to) {
        return;
    }
    let existingEdges = adjacencyList.get(from);
    if (existingEdges === undefined) {
        const sources = [];
        adjacencyList.set(from, sources);
        existingEdges = sources;
    }
    const edge = makeEdge(to, kind);
    existingEdges.push(edge);
}


/**
 * @typedef {0 | 1 | 2} EdgeKind
 * A typed edge in a {@link Digraph}, represented as a 4-bit integer. Possible values:
 * * {@link EDGE_UNTYPED}
 * * {@link EDGE_ASSIGNMENT}
 * * {@link EDGE_DEPENDENCE}
 */

/** @type {0} */
export const EDGE_UNTYPED = 0;
/** @type {1} */
export const EDGE_ASSIGNMENT = 1;
/** @type {2} */
export const EDGE_DEPENDENCE = 2;

/**
 * @constant
 * @type {number}
 * The number of bits used to represent an {@link EdgeKind} integer.
 */
const EDGE_KIND_BITS = 4;

/**
 * @constant
 * @type {number}
 * A bitmask to retrieve the {@link EdgeKind} of a {@link Edge}.
 */
const EDGE_KIND_MASK = (1 << EDGE_KIND_BITS) - 1;

/**
 * Creates a typed `Edge`.
 * @param {VertexId} target
 * @param {EdgeKind} kind
 * @returns Edge
 */
export function makeEdge(target, kind) {
    // (See `Edge` for documentation about this serialization).
    return /** @type {Edge} */ ((target << EDGE_KIND_BITS) | kind);
}

/**
 * Returns the `VertexId` of the edge's target.
 * @param {Edge} edge
 * @returns {VertexId}
 */
export function getEdgeTarget(edge) {
    // (See `Edge` for documentation about this deserialization).
    return /** @type {VertexId} */ (edge >> EDGE_KIND_BITS);
}

/**
 * Returns the type of the provided `Edge`.
 * @param {Edge} edge
 * @returns {EdgeKind}
 */
export function getEdgeKind(edge) {
    // (See `Edge` for documentation about this deserialization).
    return /** @type {EdgeKind} */ (edge & EDGE_KIND_MASK);
}
