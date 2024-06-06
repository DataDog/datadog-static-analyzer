// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

"use strict";

import {FileContext} from "ext:ddsa_lib/context_file";
import {FileContextGo} from "ext:ddsa_lib/context_file_go";
import {RootContext} from "ext:ddsa_lib/context_root";
import {RuleContext} from "ext:ddsa_lib/context_rule";
import {TreeSitterNode} from "ext:ddsa_lib/ts_node";
// TODO(JF): These are only used by the Rust runtime, which currently expects them in global scope, but
//           these should be hidden inside another object, not `globalThis`.
globalThis.FileContext = FileContext;
globalThis.FileContextGo = FileContextGo;
globalThis.RootContext = RootContext;
globalThis.RuleContext = RuleContext;
globalThis.TreeSitterNode = TreeSitterNode;

///////////
// Take all exports from `stella_compat.js` and define them within this scope.
// NOTE: This is temporary scaffolding used during the transition to `ddsa_lib::JsRuntime`.
import * as stellaCompat from "ext:ddsa_lib/stella_compat";
for (const [name, obj] of Object.entries(stellaCompat)) {
    globalThis[name] = obj;
}
///////////

import {DDSA_Console} from "ext:ddsa_lib/utility";
globalThis.console = new DDSA_Console();
