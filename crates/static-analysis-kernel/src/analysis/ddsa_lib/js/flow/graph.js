// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

import { TreeSitterFieldChildNode, TreeSitterNode } from "ext:ddsa_lib/ts_node";

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

        /**
         * A list of {@link PhiNode}. There is no significance to the ordering of the nodes.
         * @type {Array<PhiNode>}
         * @private
         */
        this.phiNodes = [];
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
    
    /**
     * Creates a new {@link PhiNode} within this `Digraph` and returns a reference to it.
     * @returns {PhiNode}
     */
    newPhiNode() {
        // An auto-incrementing id ensures uniqueness of phi node ids:
        const internalId = this.phiNodes.length;
        const phiNode = new PhiNode(/** @type {InternalId} */ (internalId));
        this.phiNodes.push(phiNode);
        return phiNode;
    }
}

/**
 * A graph node that indicates that a value can have more than one possible definition depending
 * on the control flow taken. For example:
 *
 * ```java
 * int y = 10;
 * if (condition) {
 *     y = 20;
 * } else {
 *     y = -50;
 * }
 * System.out.println(y);
 * ```
 *
 * When printing `y`, its value could be either `20` or `-50`, depending on which path was taken
 * in the if/else statement.
 * More formally, this can be represented as a function with operands describing the possible values:
 *
 * ```text
 * y0 = 10;
 * y1 = 20;
 * y2 = -50;
 * y3 = phi(y1, y2);
 * ```
 *
 * See additional documentation on {@link https://en.wikipedia.org/wiki/Static_single-assignment_form#Converting_to_SSA|phi functions}.
 */
export class PhiNode {
    /**
     * @param {InternalId} id
     */
    constructor(id) {
        /**
         * The internal id for this `PhiNode`.
         * @type {InternalId}
         */
        this.id = id;
        /**
         * A list of {@link VertexId} that are operands of this phi node.
         * @type {Array<VertexId>}
         */
        this.operands = [];
    }

    /**
     * Adds the provided {@link VertexId} as an operand.
     * @param {VertexId} vertexId
     */
    appendOperand(vertexId) {
        this.operands.push(vertexId);
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
 * @typedef {TreeSitterNode | PhiNode} Vertex
 * A vertex in a {@link Digraph}.
 */

/**
 * @typedef {0 | 1} VertexKind
 * A 1-bit integer enum indicating the type of a {@link Vertex}. Possible values:
 * * {@link VERTEX_CST}: A CST node ({@link TreeSitterNode})
 * * {@link VERTEX_PHI}: A phi node ({@link PhiNode})
 */

/** @type {0} */
export const VERTEX_CST = 0;
/** @type {1} */
export const VERTEX_PHI = 1;

/**
 * @typedef {number & { _brand: "VertexId" }} VertexId
 * An id of {@link Vertex}.
 */

/**
 * @constant
 * @type {number}
 * The number of bits used to represent a {@link VertexKind} integer.
 */
const VERTEX_KIND_BITS = 1;

/**
 * @constant
 * @type {number}
 * A bitmask to retrieve the {@link VertexKind} of a {@link VertexId}.
 */
const VERTEX_KIND_MASK = (1 << VERTEX_KIND_BITS) - 1;

/**
 * @typedef {number & { _brand: "VertexId" }} VertexId
 * An id of {@link Vertex}. Internally, this is a bit-packed representation:
 * * {@link VertexKind}: least significant bit
 * * {@link InternalId}: rest of bits
 * ```text
 *              52 bits            1 bit
 * |------------------------------|-|
 *            internalId           kind
 * ```
 * This serialization format stores the same information as an object with the shape:
 * ```js
 * const vertex = {
 *     internalId: internalId,
 *     kind: kind,
 * };
 * ```
 */

/**
 * Returns the type of the provided `VertexId`.
 * @param {VertexId} vertexId
 * @returns {VertexKind}
 */
export function vertexKind(vertexId) {
    // (See `VertexId` for documentation about how this deserialization works).
    return /** @type VertexKind */ (vertexId & VERTEX_KIND_MASK);
}

/**
 * Returns the corresponding {@link VertexId} for the provided `vertex`.
 * @param {Vertex} vertex
 * @returns {VertexId}
 */
export function vertexId(vertex) {
    if (vertex instanceof TreeSitterFieldChildNode || vertex instanceof TreeSitterNode) {
        return _asVertexId(/** @type {InternalId} */ (vertex.id), VERTEX_CST);
    } else if (vertex instanceof PhiNode) {
        return _asVertexId(/** @type {InternalId} */ (vertex.id), VERTEX_PHI);
    } else {
        throw new Error("unexpected `vertex` argument");
    }
}

/**
 * Casts the provided internal node id to a {@link VertexId} of the provided type.
 * @param {InternalId} internalId
 * @param {VertexKind} kind
 * @returns {VertexId}
 */
export function _asVertexId(internalId, kind) {
    return /** @type {VertexId} */ ((internalId << VERTEX_KIND_BITS) | kind);
}

/**
 * Returns the internal node id of the provided `vertexId`.
 * * If the vertex is a {@link VERTEX_CST}, this will be a {@link TreeSitterNode} id.
 * * If the vertex is a {@link VERTEX_PHI}, this will be a {@link PhiNode} id.
 * @param {VertexId} vertexId
 * @returns {InternalId}
 */
export function internalId(vertexId) {
    // (See `VertexId` for documentation about how this deserialization works).
    return /** @type {InternalId} */ (vertexId >> VERTEX_KIND_BITS);
}

/**
 * @typedef {number & { _brand: "InternalId" }} InternalId
 * The internal id of a node ({@link TreeSitterNode.id} or {@link PhiNode.id}) that is a vertex in a {@link Digraph}.
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
        /** @type {Array<Edge>} */
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
 * A directed flow from a {@link Digraph} vertex to a leaf vertex that represents a taint flow.
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
 */
export class TaintFlow extends Array {
    /**
     * @param {Array<VertexId>} vidPath
     * @param {boolean} isForwardFlow
     */
    constructor(vidPath, isForwardFlow) {
        /** @type {Array<TreeSitterNode>} */
        const path = [];
        for (const vertexId of vidPath) {
            // (Phi nodes are pruned from the public-facing API, but will be present in the `this._vidPath`).
            if (vertexKind(vertexId) === VERTEX_CST) {
                path.push(globalThis.__RUST_BRIDGE__ts_node.get(internalId(vertexId)));
            }
        }
        super(...path);

        /**
         * Whether this flow represents forward data flow or not. See {@link TaintFlow.path} for documentation.
         * @type {boolean}
         */
        this.isForwardFlow = isForwardFlow;

        /**
         * The path, represented as an array of {@link VertexId}.
         * @type {Array<VertexId>}
         * @private
         */
        this._vidPath = vidPath;
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
        return this.at(idx);
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
        return this.at(idx);
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

