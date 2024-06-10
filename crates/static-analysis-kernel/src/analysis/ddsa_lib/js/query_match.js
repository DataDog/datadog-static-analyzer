// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

/**
 * A collection of named captures that represents an individual "match" from a tree-sitter query.
 */
export class QueryMatch {
    /**
     * @param {Array<NamedCapture> | undefined} captures
     */
    constructor(captures) {
        /**
         * @type {Array<NamedCapture> | undefined}
         * @readonly
         * @private
         */
        this._captures = captures;
    }

    /**
     * Returns the id of the node with the given capture name. If there are multiple matching captures,
     * only the last will be returned, and the rest will be silently ignored.
     * @param {string} name
     * @returns {NodeId | undefined}
     *
     * @remarks
     * This is implemented as `O(N)` iteration instead of `O(1)` lookup because the expected number of
     * capture names is small (e.g. < 10).
     */
    get(name) {
        const len = this._captures?.length ?? 0;
        for (let i = 0; i < len; i++) {
            const item = this._captures[i];
            if (item.name === name) {
                if (item.nodeIds !== undefined) {
                    // By convention, we return the last match if there are multiple.
                    // This is guaranteed to be at least length 1, so this won't underflow.
                    return item.nodeIds[item.nodeIds.length - 1];
                } else {
                    return item.nodeId;
                }
            }
        }
        return undefined;
    }

    /**
     * Returns an array of the ids of nodes with the given capture name.
     * If this is called on a capture that is a `SingleCapture` instead of a `MultiCapture`, the capture
     * will be turned in an array as the sole element.
     * @param {string} name
     * @returns {Uint32Array | undefined}
     *
     * @remarks
     * This is implemented as `O(N)` iteration instead of `O(1)` lookup because the expected number of
     * capture names is small (e.g. < 10).
     */
    getMany(name) {
        const len = this._captures?.length ?? 0;
        for (let i = 0; i < len; i++) {
            const item = this._captures[i];
            if (item.name === name) {
                if (item.nodeIds !== undefined) {
                    return item.nodeIds;
                } else {
                    return new Uint32Array([item.nodeId]);
                }
            }
        }
        return undefined;
    }
}

/**
 * A compatibility layer to support object-style key lookup for capture names on a {@link QueryMatch}.
 *
 * ```js
 * // QueryMatchCompat layer:
 * // Note that there is no support for `getMany`.
 * const cap = captures["capture_name"];
 * ```
 * This is considered "deprecated", and this will eventually be removed, requiring rules to use:
 * ```js
 * // "Official" access pattern
 * const cap = captures.get("capture_name");
 * const caps = captures.getMany("capture_name");
 * ```
 * @deprecated
 */
export class QueryMatchCompat {
    /**
     * @param {QueryMatch} queryMatchInstance
     */
    constructor(queryMatchInstance) {
        return new Proxy(queryMatchInstance, {
            get(target, p, _receiver) {
                switch (p) {
                    // We need to special-case "get" and "getMany" because there could be a capture name that collides, e.g
                    // `(identifier) @get` or `(function_declaration) @getMany`.
                    // In this (edge) case, the standard `.get("...")` and `.getMany("...")` functions will not be accessible.
                    case "get":
                    case "getMany": {
                        let value = target.get(p);
                        if (value === undefined) {
                            // If undefined, then the code is invoking `.get("...")`, so forward the call to that function,
                            // binding it to ensure the proper `this` context.
                            return target[p].bind(target);
                        } else {
                            // Otherwise, return the capture with the name of `p`.
                            return value;
                        }
                    }
                    default:
                        // Because this property name does not collide, we know it can only be a capture name lookup
                        // using the (deprecated) object property lookup syntax.
                        return target.get(p);
                }
            },
        });
    }
}