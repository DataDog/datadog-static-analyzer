// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

const { op_console_push } = Deno.core.ops;

export class DDSA_Console {
    /**
     * Sends a string to the Rust implementation of `console`.
     * @param {...*} args
     * @returns {void}
     */
    log(...args) {
        op_console_push(`${this.constructor.stringifyAll(...args)}`);
    }

    /**
     * @param {...*} args
     * @returns {string}
     */
    static stringifyAll(...args) {
        return args.map((arg) => this.stringify(arg)).join(" ");
    }

    /**
     * Converts an unknown type to a normalized string representation.
     * @param {*} arg
     * @returns {string}
     *
     * @example
     * ```js
     * DDSA_Console.stringify(1234) === "1234";
     * DDSA_Console.stringify({ key: "value" }) === '{"key":"value"}';
     * ```
     */
    static stringify(arg) {
        switch (typeof arg) {
            case "string":
            case "bigint":
            case "number":
            case "boolean":
            case "undefined":
            case "symbol":
                return String(arg).toString();
            default:
                // `typeof null === "object"`
                if (arg === null) {
                    return "null";
                }
                // The arg is either an array or an object.
                return JSON.stringify(arg, undefined, undefined);
        }
    }
}

/**
 * An empty, sealed object.
 * @internal
 *
 * @privateRemarks
 * This is used to return an empty object without having v8 allocate a new one.
 */
export const SEALED_EMPTY_OBJECT = Object.seal({});

/**
 * An empty, sealed array.
 * @internal
 * @type {Array<any>}
 *
 * @privateRemarks
 * This is used to return an empty array without having v8 allocate a new one.
 */
export const SEALED_EMPTY_ARRAY  = Object.seal(new Array(0));
