// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

const { op_get_js_imports } = Deno.core.ops;

/**
 * A JavaScript import, which may be a module, a function, a variable, or a type.
 *
 * @typedef {Object} PackageImport
 * @property {string} name - The name of the item being imported.
 * @property {string | null} importedFrom - The package that the item is being imported from. Note that this will be `null` if we are importing the module as a whole,
 *                                          instead of a specific item from the module.
 * @property {string | null} importedAs - The alias that the item is being imported as. Note that this will be `null` if we are not aliasing the import.
 */

export class PackageImport {
  /**
   * Creates a new `PackageImport`.
   *
   * @param {string} name
   * @param {string | null} importedFrom
   * @param {string | null} importedAs
   */
  constructor(name, importedFrom, importedAs) {
    this.name = name;
    this.importedFrom = importedFrom;
    this.importedAs = importedAs;
  }

  /**
   * Returns whether this import is an alias or not.
   *
   * @returns {boolean}
   */
  isAlias() {
    return this.importedAs !== null;
  }

  /**
   * Returns whether this import is a module or not.
   *
   * @returns {boolean}
   */
  isModule() {
    return this.importedFrom === null;
  }
}

/**
 * Returns whether the given package is imported in the current file.
 *
 * @param {string} packageName
 *
 * @returns {boolean}
 */
export function jsImportsPackage(packageName) {
  const imports = op_get_js_imports(packageName);
  return imports.some((i) => i.isModule() ? i.name === packageName : i.importedFrom === packageName);
}
