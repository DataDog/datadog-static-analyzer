// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026 Datadog, Inc.


use std::collections::HashSet;
use crate::model::secret_result::SecretResult;
use common::model::language::Language;
use common::tree_sitter::tree_sitter::get_tree;

// pub fn filter_secrets_for_ast(file_content: &str, language: &Language) -> Vec<SecretResult> {
//     if let Some(tree) = get_tree(&file_content, &language) {
//
//     }
// }
