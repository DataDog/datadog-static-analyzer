// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::analysis::ddsa_lib::ops;

deno_core::extension!(
    ddsa_lib,
    ops = [
        ops::op_current_filename,
        ops::op_console_push,
        ops::op_current_ts_tree_text,
        ops::op_ts_node_named_children,
        ops::op_ts_node_parent,
        ops::op_ts_node_text,
        // Language-specific
        ops::op_java_get_bin_expr_operator,
        ops::op_digraph_adjacency_list_to_dot,
    ],
    esm_entry_point = "ext:ddsa_lib/__bootstrap.js",
    esm = [
        dir "src/analysis/ddsa_lib/js",
        "__bootstrap.js",
        "ext:ddsa_lib/context_file" = "context_file.js",
        "ext:ddsa_lib/context_file_go" = "context_file_go.js",
        "ext:ddsa_lib/context_file_js" = "context_file_js.js",
        "ext:ddsa_lib/context_file_tf" = "context_file_tf.js",
        "ext:ddsa_lib/context_root" = "context_root.js",
        "ext:ddsa_lib/context_rule" = "context_rule.js",
        "ext:ddsa_lib/context_ts_lang" = "context_ts_lang.js",
        "ext:ddsa_lib/ddsa" = "ddsa.js",
        "ext:ddsa_lib/dx_cursor" = "dx_cursor.js",
        "ext:ddsa_lib/dx_go" = "dx_go.js",
        "ext:ddsa_lib/edit" = "edit.js",
        "ext:ddsa_lib/fix" = "fix.js",
        "ext:ddsa_lib/flow/graph" = "flow/graph.js",
        "ext:ddsa_lib/flow/java" = "flow/java.js",
        "ext:ddsa_lib/query_match" = "query_match.js",
        "ext:ddsa_lib/query_match_compat" = "query_match_compat.js",
        "ext:ddsa_lib/region" = "region.js",
        "ext:ddsa_lib/stella_compat" = "stella_compat.js",
        "ext:ddsa_lib/utility" = "utility.js",
        "ext:ddsa_lib/ts_node" = "ts_node.js",
        "ext:ddsa_lib/violation" = "violation.js",
    ],
);

#[cfg(test)]
deno_core::extension!(
    ddsa_lib_cfg_test,
    ops = [ops::cfg_test_op_rust_option],
    esm = [
        dir "src/analysis/ddsa_lib/js",
        "ext:ddsa_lib_cfg_test/helpers" = "test_helpers.js",
    ]
);
