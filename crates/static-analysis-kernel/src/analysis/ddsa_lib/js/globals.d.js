// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

import {DDSA_Console} from "ext:ddsa_lib/utility";
import {RootContext} from "ext:ddsa_lib/context_root";

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
 * A lookup that maps the display name of a tree-sitter node's type to its `TSSymbol`. This is grammar-specific.
 * @name __RUST_BRIDGE__ts_symbol_lookup
 * @type {Map<string | NodeTypeId, NodeTypeId | string>}
 * @global
 */

/**
 * The context for a rule execution.
 * @name __RUST_BRIDGE__context
 * @type {RootContext}
 * @global
 */
