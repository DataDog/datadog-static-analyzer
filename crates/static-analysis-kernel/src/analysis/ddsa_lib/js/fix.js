// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

/**
 * An object containing a collection of {@link Edit}s that will fix a static analysis {@link Violation}.
 */
export class Fix {
    /**
     * @param {string} message
     * @param {Array<Edit>} edits
     */
    constructor(message, edits) {
        /**
         * A human-friendly message describing what the fix does.
         * @type {string}
         * @readonly
         * @private
         * 
         * @remarks
         * This appears, for example, in the IDE in the pop-up menu, or in a Github Pull Request when suggesting a fix.
         */
        this.message = message;
        /**
         * @type {Array<Edit>}
         * @readonly
         * @private
         */
        this.edits = edits;
    }

    /**
     * Creates a new `Fix``.
     *
     * @param {string} message
     * @param {Array<Edit>} edits
     * @returns {Fix}
     *
     * @remarks
     * This is a convenience function to allow creation of a `Fix` without using the class constructor.
     * It is functionally equivalent to calling `new Fix(...)`.
     */
    static new(message, edits) {
        return new Fix(message, edits);
    }
}
