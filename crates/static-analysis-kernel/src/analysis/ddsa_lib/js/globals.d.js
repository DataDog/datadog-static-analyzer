// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

import {DDSA_Console} from "ext:ddsa_lib/utility";
import {QueryMatch} from "ext:ddsa_lib/query_match";
import {RootContext} from "ext:ddsa_lib/context_root";
import {TreeSitterNode} from "ext:ddsa_lib/ts_node";
import {Violation} from "ext:ddsa_lib/violation";

/**
 * Global variables available within a rule execution.
 * These are populated by `__bootstrap.js`.
 */

/**
 * @name console
 * @type {DDSA_Console}
 * @global
 */

/**
 * The context for a rule execution.
 * @name __RUST_BRIDGE__context
 * @type {RootContext}
 * @global
 */

/**
 * An array storing the tree-sitter query matches and their captures. The rule's `visit` function is run against each item.
 * @name __RUST_BRIDGE__query_match
 * @type {Array<QueryMatch>}
 * @global
 */

/**
 * A map containing all the tree-sitter nodes passed from the Rust static-analysis-kernel.
 * @name __RUST_BRIDGE__ts_node
 * @type {Map<NodeId, TreeSitterNode>}
 * @global
 */

/**
 * An array storing the violations reported by the rule's JavaScript execution.
 * @name __RUST_BRIDGE__violation
 * @type {Array<Violation>}
 * @global
 */
