// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

const {
    op_current_ts_tree_text,
    op_current_filename,
} = Deno.core.ops;

/**
 * Metadata related the execution of a JavaScript rule.
 */
export class RootContext {
    /**
     * @param {FileContext} fileCtx
     * @param {RuleContext} ruleCtx
     * @param {TsLanguageContext} tsLangCtx
     */
    constructor(fileCtx, ruleCtx, tsLangCtx) {
        /**
         * The filename of the file being analyzed within this context. This is intended to be an internal
         * field. External callers should use the {@link RootContext.filename} getter.
         * @type {string | undefined}
         * @private
         */
        this.__js_cachedFilename = undefined;
        /**
         * The contents of the file. This is intended to be an internal field. External callers
         * should use the {@link RootContext.fileContents} getter.
         * @type {string | undefined}
         * @private
         */
        this.__js_cachedFileContents = undefined;
        /**
         * An object that provides extra metadata for a specific filetypes.
         * @type {FileContext}
         * @private
         */
        this.fileCtx = fileCtx;
        /**
         * An object that provides extra metadata specific to a rule.
         * @type {RuleContext}
         * @private
         */
        this.ruleCtx = ruleCtx;
        /**
         * An object that provides metadata specific to a tree-sitter Language.
         * @type {TsLanguageContext}
         * @private
         */
        this.tsLangCtx = tsLangCtx;
    }

    /**
     * A getter for the contents of the entire file.
     * @returns {string}
     */
    get fileContents() {
        if (this.__js_cachedFileContents === undefined) {
            this.__js_cachedFileContents = op_current_ts_tree_text();
        }
        return this.__js_cachedFileContents;
    }

    /**
     * A getter for the name of the file.
     *
     * @remarks
     * This lazily makes a call to Rust to retrieve the filename. Subsequent calls to this getter will
     * return the cached value.
     *
     * @returns {string}
     */
    get filename() {
        if (this.__js_cachedFilename === undefined) {
            this.__js_cachedFilename = op_current_filename();
        }
        return this.__js_cachedFilename;
    }
}
