// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

"use strict";

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
