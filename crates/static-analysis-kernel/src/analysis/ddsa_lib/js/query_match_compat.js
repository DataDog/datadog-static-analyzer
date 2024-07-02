// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

/**
 * A compatibility layer to support the stella API for a {@link QueryMatch}.
 *
 * ```js
 * // QueryMatchCompat layer:
 * const query = new QueryMatchCompat(queryMatchInstance); // Done by the Rust bridge
 * const cap = query.captures["capture_name"];
 * const caps = query.capturesList["capture_name"];
 * const code = query.context.code;
 * const arg1 = query.context.arguments["argName"];
 * ```
 * This is considered "deprecated", and this will eventually be removed, requiring rules to use:
 * ```js
 * // "Official" access pattern
 * const captures = new QueryMatch(captures); // Done by the Rust bridge
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
        const __capturesProxy = new Proxy(queryMatchInstance ?? {}, {
            get(target, p, _receiver) {
                return target.get(p);
            },
        });

        return new Proxy(queryMatchInstance ?? {}, {
            get(target, p, _receiver) {
                switch (p) {
                    // stella compatibility layer
                    ////////////////////////////////////////////////////////////////////////////////////////////////////
                    case "captures":
                        // We created this eagerly because it's common for rule code to call `query.captures` multiple
                        // times, and we don't want to generate a new Proxy each time.
                        return __capturesProxy;
                    case "capturesList":
                        // `capturesList` is not commonly called, so lazily create this Proxy.
                        return new Proxy(target, {
                            get(target, p, _receiver) {
                                return target.getMany(p);
                            },
                        });
                    case "context":
                        // `context` is not commonly called, so lazily create this Proxy.
                        return new Proxy({}, {
                            get(target, p, _receiver) {
                                switch (p) {
                                    case "arguments":
                                        return new Proxy(globalThis.__RUST_BRIDGE__context.ruleCtx, {
                                            get(target, p, _receiver) {
                                                return target.getArgument(p);
                                            },
                                        });
                                    case "code":
                                        return globalThis.__RUST_BRIDGE__context.fileContents;
                                    case "filename":
                                        return globalThis.__RUST_BRIDGE__context.filename;
                                    case "packages":
                                        return globalThis.__RUST_BRIDGE__context.fileCtx.go.packages;
                                    default:
                                        return undefined;
                                }
                            },
                        });
                    //
                    // native ddsa API pass-through:
                    ////////////////////////////////////////////////////////////////////////////////////////////////////
                    case "get":
                    case "getMany":
                    case "_getId":
                    case "_getManyIds":
                        return target[p].bind(target);
                    default:
                        return undefined;
                }
            }
        });
    }
}
