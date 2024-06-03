// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

import {SEALED_EMPTY_ARRAY} from "ext:ddsa_lib/utility";

/**
 * A fully-qualified package name.
 * @example
 * For the given import:
 * ```
 * import (
 *     procstatsd "github.com/DataDog/datadog-agent/pkg/process/statsd"
 * )
 * ```
 * the fully-qualified package name is `github.com/DataDog/datadog-agent/pkg/process/statsd`.
 * @typedef {string} PackageFullyQualifiedName
 */

/**
 * An alias for an imported package.
 * @example
 * For the given import:
 * ```
 * import (
 *     procstatsd "github.com/DataDog/datadog-agent/pkg/process/statsd"
 * )
 * ```
 * the alias is `procstatsd`.
 * @typedef {string} PackageAlias
 */

/**
 * Metadata about a `go` file.
 */
export class FileContextGo {
    /**
     * Creates a new `FileContextGo`.
     * @param {Map<PackageAlias, PackageFullyQualifiedName> | undefined} aliasMap
     */
    constructor(aliasMap) {
        /**
         * A map from a package alias to its fully-qualified name.
         * @type {Map<PackageAlias, PackageFullyQualifiedName> | undefined}
         * */
        this.aliasMap = aliasMap;
    }

    /**
     * Returns the fully-qualified name of a package, given an input alias.
     * @param {string} alias
     * @returns {string | undefined}
     */
    getResolvedPackage(alias) {
        return this.aliasMap?.get(alias);
    }

    /**
     * Returns an array of fully qualified package names in an arbitrary order.
     * @returns {Array<PackageFullyQualifiedName>}
     */
    get packages() {
        // For implementation simplicity, we are de-duplicating the FQ package names by
        // allocating a Set on every call and then returning it. Should this become a performance
        // bottleneck, this will be refactored so the Set is pre-generated/cached.
        if (this.aliasMap === undefined) {
            return SEALED_EMPTY_ARRAY;
        } else {
            const uniquePackages = new Set(this.aliasMap.values());
            return Array.from(uniquePackages);
        }
    }
}
