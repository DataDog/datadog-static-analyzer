import { DxCursor } from "./dx_cursor";

/** @typedef {{node: DxCursor, name: DxCursor, [type]: DxCursor, [value]: DxCursor}} Declaration */

/** @typedef {{node: DxCursor, name: DxCursor, [value]: DxCursor}} Assignment */

export class DxGo {
    /**
     * Returns the node where a name (variable, constant, function, package) is declared.
     * @param {TreeSitterNode | TreeSitterFieldChildNode | DxCursor} node The node containing the identifier whose name we want to find a declaration point for.
     * @returns {Declaration | undefined}
     */
    getDeclarationSite(node) {
        let cursor = DxCursor.from(node);
        if (cursor.cstType === "selector_expression") {
            cursor = cursor.fieldOfType("operand", "identifier");
        }
        if (cursor === undefined || cursor.cstType !== "identifier")
            return undefined;
        const name = node.text;
        cursor = cursor.predecessor();
        while (cursor !== undefined) {
            let varDecl = this.findNameDeclaration(name, cursor);
            if (varDecl !== undefined) return varDecl;
            cursor = cursor.predecessor();
        }
        return undefined;
    }

    /**
     * Returns an array of nodes where a variable might be assigned its current value.
     * TODO: Not supported: fields, pointers, closure or global variable assignment in functions
     * @param {TreeSitterNode | TreeSitterFieldChildNode | DxCursor} node The node containing the identifier whose name we want to find a declaration point for.
     * @returns {Array<Assignment>}
     */
    getAssignmentSites(node) {
        let useSite = DxCursor.from(node);
        if (useSite.cstType !== "identifier") return [];
        const name = useSite.text;

        return this.resolveAssignmentsFromUseSite(name, useSite).sites;
    }

    /**
     * @param {string} name
     * @param {DxCursor} cursor
     * @returns {Declaration | undefined}
     */
    findNameDeclaration(name, cursor) {
        let decl = this.parseNameDeclaration(name, cursor);
        if (decl !== undefined) return decl;
        switch (cursor.cstType) {
            case "if_statement":
            case "expression_switch_statement":
                return cursor
                    .childrenOfType("initializer")
                    .map((n) => this.parseNameDeclaration(name, n))
                    .find((n) => n !== undefined);
            case "for_statement": {
                let inRange = cursor
                    .childrenOfType("range_clause")
                    .flatMap((n) => n.fieldsOfType("left", "expression_list"))
                    .flatMap((n) => n.childrenOfType("identifier"))
                    .find((n) => n.text === name);
                if (inRange !== undefined) return { node: cursor, name: inRange };
                return cursor
                    .childrenOfType("for_clause")
                    .flatMap((n) => n.fields("initializer"))
                    .map((n) => this.parseNameDeclaration(name, n))
                    .find((n) => n !== undefined);
                break;
            }
            case "function_declaration": {
                let params = [
                    ...cursor.fieldsOfType("parameters", "parameter_list"),
                    ...cursor.fieldsOfType("result", "parameter_list"),
                ].flatMap((n) => n.childrenOfType("parameter_declaration"));
                for (let param of params) {
                    let paramType = param.field("type");
                    let paramName = param
                        .fieldsOfType("name", "identifier")
                        .find((n) => n.text === name);
                    if (paramName !== undefined)
                        return { node: param, name: paramName, type: paramType };
                }
            }
        }
        return undefined;
    }

    /**
     * @param {string} name
     * @param {DxCursor} cursor
     * @return {Declaration | undefined}
     */
    parseNameDeclaration(name, cursor) {
        switch (cursor.cstType) {
            case "var_declaration": {
                for (let spec of cursor.childrenOfType("var_spec")) {
                    let varName = spec
                        .fieldsOfType("name", "identifier")
                        .find((n) => n.text === name);
                    let type = spec.field("type");
                    let value = spec.field("value");
                    if (varName !== undefined)
                        return { node: cursor, name: varName, type, value };
                }
                return undefined;
            }
            case "const_declaration": {
                for (let spec of cursor.childrenOfType("const_spec")) {
                    let constName = spec
                        .fieldsOfType("name", "identifier")
                        .find((n) => n.text === name);
                    let type = spec.field("type");
                    let value = spec.field("value");
                    if (constName !== undefined)
                        return { node: cursor, name: constName, type, value };
                }
                return undefined;
            }
            case "short_var_declaration": {
                let left = cursor
                    .fieldOfType("left", "expression_list")
                    .childrenOfType("identifier");
                let right = cursor.fieldOfType("right", "expression_list").children();
                let idx = left.findIndex(
                    (n) => n.cstType === "identifier" && n.text === name
                );
                if (left.length === right.length) {
                    return idx >= 0
                        ? { node: cursor, name: left[idx], value: right[idx] }
                        : undefined;
                } else if (right.length === 1) {
                    return idx >= 0
                        ? { node: cursor, name: left[idx], value: right[0] }
                        : undefined;
                } else {
                    return undefined;
                }
            }
            case "function_declaration": {
                let fnName = cursor.fieldOfType("name", "identifier");
                if (fnName.text === name) return { node: fnName, name: fnName };
                return undefined;
            }
            case "package_clause": {
                let pkgName = cursor
                    .childrenOfType("package_identifier")
                    .find((n) => n.text === name);
                return pkgName !== undefined
                    ? { node: cursor, name: pkgName }
                    : undefined;
            }
            case "import_declaration": {
                let specs = [
                    ...cursor.childrenOfType("import_spec"),
                    ...cursor
                        .childrenOfType("import_spec_list")
                        .flatMap((c) => c.childrenOfType("import_spec")),
                ];
                for (let spec of specs) {
                    let pkgName = spec.fieldOfType("name", "package_identifier");
                    let path = spec.fieldOfType("path", "interpreted_string_literal");
                    if (pkgName === undefined) {
                        if (path.text.endsWith(`/${name}"`))
                            return { node: cursor, name: path };
                    } else if (pkgName.text === name) {
                        return { node: cursor, name: pkgName };
                    }
                }
                return undefined;
            }
            default:
                return undefined;
        }
    }

    /**
     * Traverses from the use site up to the root, keeping track of where a variable with the given name
     * was assigned a value. At some point, due to if/for/switch statements, there could be several paths
     * where a variable might have received its value, and a path is closed as long as we know all of the
     * assignment sites along that path. We stop iterating when we reach the root or when all paths are closed.
     * @param {string} name
     * @param {DxCursor} useSite
     * @return {{closed: boolean, sites: Array<Assignment>}}
     */
    resolveAssignmentsFromUseSite(name, useSite) {
        let closed = false;
        let sites = [];
        let cursor = useSite.predecessor();
        while (cursor !== undefined) {
            // We use "predecessor" to traverse, which means that sometimes we are on the direct upwards path from the
            // use site (an ancestor) and sometimes we are on a little side path (a statement occurring before the use
            // site). This is important because, when we hit certain statements and we are on the upwards path, it
            // means that we have already processed them, while if we are not on the upwards path, it means that we
            // need to process them explicitly.
            let inUpwardsPath = useSite.descendsFrom(cursor);
            switch (cursor.cstType) {
                case "short_var_declaration":
                case "assignment_statement": {
                    // If on the upwards path, this is an assignment that the use site participates in
                    // (so the assignment really happens after the usage.)
                    if (inUpwardsPath) break;
                    let { closed: cl, sites: si } = this.resolveAssignmentsOrShortDecls(
                        name,
                        cursor
                    );
                    closed = cl;
                    sites.push(...si);
                    break;
                }
                case "var_declaration": {
                    let { closed: cl, sites: si } = this.resolveAssignmentsInVarConstDecl(
                        name,
                        cursor,
                        cursor.childrenOfType("var_spec")
                    );
                    closed = cl;
                    sites.push(...si);
                    break;
                }
                case "const_declaration": {
                    let { closed: cl, sites: si } = this.resolveAssignmentsInVarConstDecl(
                        name,
                        cursor,
                        cursor.childrenOfType("const_spec")
                    );
                    closed = cl;
                    sites.push(...si);
                    break;
                }
                case "for_statement": {
                    // If on the upwards path, we have already processed the body and the initializers, but we need
                    // to process the body again because a 'for' loop... well, loops. So a statement at the end
                    // of the block might affect the use site on the next go-around.
                    // Otherwise, we process the for statement as usual.
                    if (inUpwardsPath) {
                        let block = cursor.fieldOfType("body", "block");
                        if (!block) break;
                        let { sites: si } = this.resolveAssignmentsInBlock(name, block);
                        sites.push(...si);
                    } else {
                        let { closed: cl, sites: si } =
                            this.resolveAssignmentsInForStatement(name, cursor);
                        closed = cl;
                        sites.push(...si);
                    }
                    break;
                }
                case "if_statement": {
                    // If on the upwards path, we have already processed the branch that the use site is on.
                    if (inUpwardsPath) break;
                    let { closed: cl, sites: si } = this.resolveAssignmentsInIfStatement(
                        name,
                        cursor
                    );
                    closed = cl;
                    sites.push(...si);
                    break;
                }
                case "expression_switch_statement":
                case "select_statement": {
                    // If on the upwards path, we have already processed the branch that the use site is on.
                    if (inUpwardsPath) break;
                    let { closed: cl, sites: si } =
                        this.resolveAssignmentsInSwitchSelectStatement(name, cursor);
                    closed = cl;
                    sites.push(...si);
                    break;
                }
                case "block": {
                    // If on the upwards path, we have already processed the block.
                    if (inUpwardsPath) break;
                    let { closed: cl, sites: si } = this.resolveAssignmentsInBlock(
                        name,
                        cursor
                    );
                    closed = cl;
                    sites.push(...si);
                    break;
                }
                case "function_declaration": {
                    // If we are not on the upwards path, we ignore the function declaration (it won't affect
                    // the variables in the use site.
                    if (!inUpwardsPath) break;
                    // Otherwise, we need to check the parameters and returns to see if the variable is defined there.
                    let params = [
                        ...cursor.fieldsOfType("parameters", "parameter_list"),
                        ...cursor.fieldsOfType("result", "parameter_list"),
                    ].flatMap((n) => n.childrenOfType("parameter_declaration"));
                    for (let param of params) {
                        let paramName = param
                            .fieldsOfType("name", "identifier")
                            .find((n) => n.text === name);
                        if (paramName !== undefined) {
                            closed = true;
                            sites.push({ node: param, name: paramName });
                        }
                    }
                    break;
                }
            }
            if (closed) break;
            cursor = cursor.predecessor();
        }
        return { closed, sites };
    }

    /**
     * Traverses a block, looking for assignment sites for the variable with the given name.
     * @param {string} name
     * @param {DxCursor} block
     * @return {{closed: boolean, sites: Array<Assignment>}}
     */
    resolveAssignmentsInBlock(name, block) {
        let closed = false;
        let sites = [];
        let cursor = block.lastChild();
        while (cursor !== undefined) {
            // We only look for usage sites if we are not closed. However, if we find a variable declaration with
            // that name, it means that the usage sites we found so far are invalid and we are open again. So we
            // need to check the whole block in any case.
            //
            // (We can do this because this function is not called when the declaration is in the direct execution
            // path for the use site, so any declarations we find here do not affect the use site.)
            if (this.parseNameDeclaration(name, cursor) !== undefined) {
                closed = false;
                sites = [];
            } else if (!closed) {
                let { closed: cl, sites: si } = this.resolveAssignmentsInStatement(
                    name,
                    cursor
                );
                closed = cl;
                sites.push(...si);
            }
            cursor = cursor.prevSibling();
        }
        return { closed, sites };
    }

    /**
     * Checks if a variable was assigned a value in a statement.
     * @param {string} name
     * @param {DxCursor} cursor
     * @returns {{closed: boolean, sites: Array<Assignment>}}
     */
    resolveAssignmentsInStatement(name, cursor) {
        // These are the statements that could result in a variable being assigned a value (directly or indirectly),
        // so we detect the statement type and dispatch appropriately.
        switch (cursor.cstType) {
            case "short_var_declaration":
            case "assignment_statement":
                return this.resolveAssignmentsOrShortDecls(name, cursor);
            case "var_declaration":
                return this.resolveAssignmentsInVarConstDecl(
                    name,
                    cursor,
                    cursor.childrenOfType("var_spec")
                );
            case "const_declaration":
                return this.resolveAssignmentsInVarConstDecl(
                    name,
                    cursor,
                    cursor.childrenOfType("const_spec")
                );
            case "for_statement":
                return this.resolveAssignmentsInForStatement(name, cursor);
            case "if_statement":
                return this.resolveAssignmentsInIfStatement(name, cursor);
            case "expression_switch_statement":
            case "select_statement":
                return this.resolveAssignmentsInSwitchSelectStatement(name, cursor);
            case "block":
                return this.resolveAssignmentsInBlock(name, cursor);
        }
        return { closed: false, sites: [] };
    }

    /**
     * Checks if a variable was assigned a value in an assignment or short declaration.
     * @param {string} name
     * @param {DxCursor} cursor
     * @returns {{closed: boolean, sites: Array<Assignment>}}
     */
    resolveAssignmentsOrShortDecls(name, cursor) {
        let left = cursor
            .fieldOfType("left", "expression_list")
            ?.childrenOfType("identifier");
        let right = cursor.fieldOfType("right", "expression_list")?.children();
        if (!left || !right) return { closed: false, sites: [] };
        let idx = left.findIndex((n) => n.text === name);
        if (idx < 0) return { closed: false, sites: [] };
        if (left.length === right.length) {
            return {
                closed: true,
                sites: [{ node: cursor, name: left[idx], value: right[idx] }],
            };
        }
        if (right.length === 1) {
            return {
                closed: true,
                sites: [{ node: cursor, name: left[idx], value: right[0] }],
            };
        }
        return { closed: true, sites: [{ node: cursor, name: left[idx] }] };
    }

    /**
     * Checks if a name was assigned a value in a variable or constant declaration.
     * @param {string} name
     * @param {DxCursor} cursor
     * @param {Array<DxCursor>} specs
     * @returns {{closed: boolean, sites: Array<Assignment>}}
     */
    resolveAssignmentsInVarConstDecl(name, cursor, specs) {
        for (let spec of specs) {
            let names = spec.fieldsOfType("name", "identifier");
            let type = spec.field("type");
            let values =
                spec.fieldOfType("value", "expression_list")?.children() || [];
            let idx = names.findIndex((n) => n.text === name);
            if (idx < 0) continue;
            if (names.length === values.length) {
                return {
                    closed: true,
                    sites: [
                        { node: cursor, name: names[idx], type: type, value: values[idx] },
                    ],
                };
            }
            if (values.length === 1) {
                return {
                    closed: true,
                    sites: [
                        { node: cursor, name: names[idx], type: type, value: values[0] },
                    ],
                };
            }
            return {
                closed: true,
                sites: [{ node: cursor, name: names[idx], type: type }],
            };
        }
        return { closed: false, sites: [] };
    }

    /**
     * Checks if a variable was assigned a value in a for statement.
     * @param {string} name
     * @param {DxCursor} cursor
     * @returns {{closed: boolean, sites: Array<Assignment>}}
     */
    resolveAssignmentsInForStatement(name, cursor) {
        let body = cursor.fieldOfType("body", "block");
        if (body === undefined) return { closed: false, sites: [] };
        let { closed, sites } = this.resolveAssignmentsInBlock(name, body);
        if (closed) return { closed, sites };
        let forClause = cursor.childrenOfType("for_clause")[0];
        let rangeClause = cursor.childrenOfType("range_clause")[0];
        if (forClause !== undefined) {
            let initializer = forClause.field("initializer");
            if (initializer !== undefined) {
                let { closed: cl, sites: si } = this.resolveAssignmentsInStatement(
                    name,
                    initializer
                );
                closed = closed && cl;
                sites.push(...si);
            }
        } else if (rangeClause !== undefined) {
            let left = rangeClause.fieldOfType("left", "expression_list");
            if (left !== undefined) {
                let found = left
                    .childrenOfType("identifier")
                    .find((n) => n.text === name);
                if (found !== undefined) {
                    closed = true;
                    sites.push({ node: rangeClause, name: found });
                }
            }
        }
        return { closed, sites };
    }

    /**
     * Checks if a variable was assigned a value in an if statement.
     * @param {string} name
     * @param {DxCursor} cursor
     * @returns {{closed: boolean, sites: Array<Assignment>}}
     */
    resolveAssignmentsInIfStatement(name, cursor) {
        let consequence = cursor.fieldOfType("consequence", "block");
        let alternative = cursor.fieldOfType("alternative", "block");
        if (consequence === undefined) return { closed: false, sites: [] };
        let { closed, sites } = this.resolveAssignmentsInBlock(name, consequence);
        if (alternative === undefined) {
            closed = false;
        } else {
            let { closed: cl, sites: si } = this.resolveAssignmentsInBlock(
                name,
                alternative
            );
            closed = closed && cl;
            sites.push(...si);
        }
        if (!closed) {
            let initializer = cursor.field("initializer");
            if (initializer !== undefined) {
                let { closed: cl, sites: si } = this.resolveAssignmentsInStatement(
                    name,
                    initializer
                );
                closed = closed && cl;
                sites.push(...si);
            }
        }
        return { closed, sites };
    }

    /**
     * Checks if a variable was assigned a value in a switch or select statement.
     * @param {string} name
     * @param {DxCursor} cursor
     * @returns {{closed: boolean, sites: Array<Assignment>}}
     */
    resolveAssignmentsInSwitchSelectStatement(name, cursor) {
        let clauses = [
            ...cursor.childrenOfType("expression_case"),
            ...cursor.childrenOfType("communication_case"),
            ...cursor.childrenOfType("default_case"),
        ];
        let maybeClosed = false;
        let closed = true;
        let sites = [];
        for (let clause of clauses) {
            let { closed: cl, sites: si } =
                this.resolveAssignmentsInSwitchSelectClause(name, clause);
            closed &&= cl;
            sites.push(...si);
            if (clause.cstType === "default_case") maybeClosed = true;
        }
        closed = closed && maybeClosed;
        if (closed) return { closed, sites };
        let initializer = cursor.field("initializer");
        if (initializer !== undefined) {
            let { closed: cl, sites: si } = this.resolveAssignmentsInStatement(
                name,
                initializer
            );
            closed = cl;
            sites.push(...si);
        }
        return { closed, sites };
    }

    /**
     * Checks if a variable was assigned a value in a case or default clause.
     * @param {string} name
     * @param {DxCursor} clause
     * @returns {{closed: boolean, sites: Array<Assignment>}}
     */
    resolveAssignmentsInSwitchSelectClause(name, clause) {
        let closed = false;
        let sites = [];
        let cursor = clause.lastChild();
        while (cursor !== undefined) {
            if (cursor.fieldName === "value") {
                cursor = cursor.prevSibling();
                continue;
            }
            let { closed: cl, sites: si } = this.resolveAssignmentsInStatement(
                name,
                cursor
            );
            closed = cl;
            sites.push(...si);
            if (closed) break;
            cursor = cursor.prevSibling();
        }
        return { closed, sites };
    }
}
