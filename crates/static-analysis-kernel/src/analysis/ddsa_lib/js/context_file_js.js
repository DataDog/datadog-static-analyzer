// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

export class FileContextJavaScript {
  /**
   * Creates a new `FileContextJavaScript`.
   * @param {PackageImport[]} packageImports
   */
  constructor(packageImports) {
    /**
     * The imports in the current file.
     * @type {PackageImport[]}
     */
    this.imports = packageImports;
  }

  /**
   * Returns whether the given package is imported in the current file.
   *
   * @param {string} packageName
   *
   * @returns {boolean}
   */
  importsPackage(packageName) {
    return this.imports.some((i) => {
      if (i.isModule()) {
        return i.name === packageName;
      }
      return i.importedFrom === packageName
    });
  }
}

/**
 * @private
 */
export class PackageImport {
  /**
   * Creates a new `PackageImport`.
   *
   * @param {string} name
   * @param {string | undefined} importedFrom
   */
  constructor(name, importedFrom) {
    /**
     * The name of the item being imported.
     * @type {string}
     */
    this.name = name;
    /**
     * The package that the item is being imported from. Note that this will be `undefined` if we are
     * importing the module as a whole, instead of a specific item from the module.
     * @type {string | undefined}
     */
    this.importedFrom = importedFrom;
  }

  /**
   * Returns whether this import is a module or not.
   *
   * @returns {boolean}
   */
  isModule() {
    return this.importedFrom === undefined;
  }
}
