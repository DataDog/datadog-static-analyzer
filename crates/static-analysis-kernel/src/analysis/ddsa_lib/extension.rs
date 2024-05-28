// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::analysis::ddsa_lib::ops;

deno_core::extension!(
    ddsa_lib,
    ops = [
        ops::op_console_push,
    ],
    esm_entry_point = "ext:ddsa_lib/__bootstrap.js",
    esm = [ dir "src/analysis/ddsa_lib/js", "__bootstrap.js" ],
    esm_with_specifiers = [
        dir "src/analysis/ddsa_lib/js",
        ("ext:ddsa_lib/edit", "edit.js"),
        ("ext:ddsa_lib/fix", "fix.js"),
        ("ext:ddsa_lib/stella_compat", "stella_compat.js"),
        ("ext:ddsa_lib/utility", "utility.js"),
        ("ext:ddsa_lib/violation", "violation.js"),
    ],
);
