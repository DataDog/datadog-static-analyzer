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

/**
 * A directed flow from a {@link Digraph} vertex to a leaf vertex.
 */
export class TaintFlow {
    /**
     * @param {Array<VertexId>} vidPath
     * @param {boolean} isForwardFlow
     */
    constructor(vidPath, isForwardFlow) {
        /**
         * Whether this flow represents forward data flow or not. See {@link TaintFlow.path} for documentation.
         * @type {boolean}
         */
        this.isForwardFlow = isForwardFlow;

        /**
         * The path, represented as an array of {@link VertexId}.
         * @type {Array<VertexId>}
         */
        this._vidPath = vidPath;

        /**
         * An array of CST nodes representing taint flow.
         *
         * If this is a forward flow (i.e. `isForwardFlow === true`), this path represents:
         * ```
         * 0         1         2         3         4         n
         * |_________|_________|_________|_________|_________|_________|
         *   source                                              sink
         * ```
         *
         * If this is a backwards flow (i.e. `isForwardFlow === false`), this path represents:
         * ```
         * 0         1         2         3         4         n
         * |_________|_________|_________|_________|_________|_________|
         *    sink                                              source
         * ```
         * @type {Array<TreeSitterNode>}
         */
        this.path = vidPath.map((vid) => globalThis.__RUST_BRIDGE__ts_node.get(/** @type {NodeId} */ (vid)));
    }

    /**
     * A getter returning the source node for this flow.
     * @returns {TreeSitterNode}
     */
    get source() {
        /** @type {number} */
        let idx;
        if (this.isForwardFlow) {
            idx = 0;
        } else {
            idx = -1;
        }
        return this.path.at(idx);
    }

    /**
     * A getter returning the sink node for this flow.
     * @returns {TreeSitterNode}
     */
    get sink() {
        /** @type {number} */
        let idx;
        if (this.isForwardFlow) {
            idx = -1;
        } else {
            idx = 0;
        }
        return this.path.at(idx);
    }
}

/**
 * Returns all valid paths from the provided `startVid` to any leaf vertex, given the adjacency list.
 * @param {AdjacencyList} adjList
 * @param {VertexId} startVid The vertex id to start traversal at.
 * @param {boolean} isForwardFlow A pass-through boolean used to initialize the resultant {@link TaintFlow}s.
 * @returns {Array<TaintFlow>}
 */
export function _findTaintFlows(adjList, startVid, isForwardFlow) {
    /** @type {[VertexId, Array<VertexId>]} */
    const queue = [[startVid, [startVid]]];
    /** @type {Array<TaintFlow>} */
    const flows = [];

    while (queue.length > 0) {
        const item = queue.shift();
        /** @type {VertexId} */
        const currentVid = item[0];
        /** @type {Array<VertexId>} */
        const currentPath = item[1];

        const edges = adjList.get(currentVid);
        if (edges === undefined) {
            if (currentPath.length > 1) {
                const flow = new TaintFlow(currentPath, isForwardFlow);
                flows.push(flow);
            }
            continue;
        }

        for (const edge of edges) {
            const targetVid = getEdgeTarget(edge);

            if (currentPath.includes(targetVid)) {
                continue;
            }

            // If there are multiple edges, we need to clone the array because each edge represents a branching point,
            // and so each needs its own copy of the historical path up to this point.
            if (edges.length > 1) {
                const nextPath = [...currentPath];
                nextPath.push(targetVid);
                queue.push([targetVid, nextPath]);
            } else {
                // Otherwise, we can just keep mutating and passing in the same array:
                currentPath.push(targetVid);
                queue.push([targetVid, currentPath]);
            }
        }
    }

    return flows;
}

/**
 * Transposes a digraph.
 * @param {AdjacencyList} adjList
 * @returns {AdjacencyList}
 */
export function transpose(adjList) {
    /** @type {AdjacencyList} */
    const transposed = new Map();

    for (const [vid, edgeList] of adjList.entries()) {
        for (const edge of edgeList) {
            const target = getEdgeTarget(edge);
            const kind = getEdgeKind(edge);
            let targetEdgeList = transposed.get(target);
            if (targetEdgeList === undefined) {
                targetEdgeList = [];
                transposed.set(target, targetEdgeList);
            }
            targetEdgeList.push(makeEdge(vid, kind));
        }
    }

    return transposed;
}

