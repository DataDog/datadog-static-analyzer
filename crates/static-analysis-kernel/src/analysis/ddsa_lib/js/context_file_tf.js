// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

/**
 * An object representing a resource within a `Terraform` file.
 * @typedef {Object} TerraformResource
 * @property {string} type
 * @property {string} name
 */

export class FileContextTerraform {
    /**
     * Creates a new `FileContextTerraform`.
     * @param {Resource[]} resourceList
     */
    constructor(resourceList) {
        /**
         * A list of resources within the file.
         * @type {Resource[]}
         * */
        this.resources = resourceList;
    }

    /**
     * Returns whether the file has a resource with the given type and name.
     * @param {string} type
     * @param {string} name
     * @returns {boolean}
     */
    hasResource(type, name) {
        return this.resources.some(resource => resource.type === type && resource.name === name);
    }

    /**
     * Returns the resources with the given type.
     * @param {string} type
     * @returns {TerraformResource[]}
     */
    getResourcesOfType(type) {
        return this.resources.filter(resource => resource.type === type);
    }
}

export class TerraformResource {
    /**
     * @param {string} type
     * @param {string} name
     */
    constructor(type, name) {
        /**
        * The type of the resource.
        * @type {string}
        */
        this.type = type;

        /**
         * The name of the resource.
         * @type {string}
         */
        this.name = name;
    }
}
