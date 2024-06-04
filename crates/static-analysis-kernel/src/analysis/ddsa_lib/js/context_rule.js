// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

/**
 * A context related to the rule that is currently executing.
 */
export class RuleContext {
    /**
     * @param {Map<string, string> | undefined} args
     */
    constructor(args) {
        /**
         * A `Map` from the argument name to its string value.
         * @type { Map<string, string> | undefined}
         * @private
         */
        this._arguments = args;
    }

    /**
     * Gets the value of the argument with the given name, if it exists.
     * @param {string} name
     * @return {string | undefined}
     *
     * Arguments are defined by the Rust static analysis kernel, and come from user-defined rule overrides.
     */
    getArgument(name) {
        return this._arguments?.get(name);
    }
}
