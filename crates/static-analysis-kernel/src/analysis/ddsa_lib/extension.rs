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
        "context_file.js" with_specifier "ext:ddsa_lib/context_file",
        "context_file_go.js" with_specifier "ext:ddsa_lib/context_file_go",
        "context_file_js.js" with_specifier "ext:ddsa_lib/context_file_js",
        "context_file_tf.js" with_specifier "ext:ddsa_lib/context_file_tf",
        "context_root.js" with_specifier "ext:ddsa_lib/context_root",
        "context_rule.js" with_specifier "ext:ddsa_lib/context_rule",
        "context_ts_lang.js" with_specifier "ext:ddsa_lib/context_ts_lang",
        "ddsa.js" with_specifier "ext:ddsa_lib/ddsa",
        "edit.js" with_specifier "ext:ddsa_lib/edit",
        "fix.js" with_specifier "ext:ddsa_lib/fix",
        "flow/graph.js" with_specifier "ext:ddsa_lib/flow/graph",
        "flow/java.js" with_specifier "ext:ddsa_lib/flow/java",
        "query_match.js" with_specifier "ext:ddsa_lib/query_match",
        "query_match_compat.js" with_specifier "ext:ddsa_lib/query_match_compat",
        "region.js" with_specifier "ext:ddsa_lib/region",
        "stella_compat.js" with_specifier "ext:ddsa_lib/stella_compat",
        "utility.js" with_specifier "ext:ddsa_lib/utility",
        "ts_node.js" with_specifier "ext:ddsa_lib/ts_node",
        "violation.js" with_specifier "ext:ddsa_lib/violation",
    ],
);

#[cfg(test)]
deno_core::extension!(
    ddsa_lib_cfg_test,
    ops = [ops::cfg_test_op_rust_option],
    esm = [
        dir "src/analysis/ddsa_lib/js",
        "test_helpers.js" with_specifier "ext:ddsa_lib_cfg_test/helpers",
    ]
);
