// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

/**
 * Metadata related to a specific filetype.
 */
export class FileContext {
    /**
     * Creates a new, empty `FileContext`.
     */
    constructor() {
        /**
         * A `go` file context.
         * @type {FileContextGo | undefined}
         */
        this.go = undefined;
    }
}
