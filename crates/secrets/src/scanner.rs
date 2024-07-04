// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::model::secret_result::{SecretResult, SecretResultMatch};
use crate::model::secret_rule::SecretRule;
use common::analysis_options::AnalysisOptions;
use common::model::position::Position;
use itertools::Itertools;
use sds::{RuleConfig, Scanner};

/// Build the SDS scanner used to scan all code using the rules fetched from
/// our API.
///
/// Once the scanner is built, use scanner.scan() to find secrets.
pub fn build_sds_scanner(rules: &Vec<SecretRule>) -> Scanner {
    let sds_rules = rules
        .iter()
        .map(|r| r.convert_to_sds_ruleconfig())
        .collect::<Vec<RuleConfig>>();
    Scanner::new(&sds_rules).unwrap()
}

pub struct Result {
    pub rule_id: String,
    pub rule_index: usize,
    pub start: Position,
    pub end: Position,
}

/// Find secrets in code
pub fn find_secrets(
    scanner: &Scanner,
    sds_rules: &[SecretRule],
    filename: &str,
    code: &str,
    _options: &AnalysisOptions,
) -> Vec<SecretResult> {
    let mut codemut = code.to_owned();
    let matches = scanner.scan(&mut codemut);

    if matches.is_empty() {
        return vec![];
    }

    matches
        .iter()
        .map(|sds_match| Result {
            rule_id: sds_rules[sds_match.rule_index].id.clone(),
            rule_index: sds_match.rule_index,
            start: Position { line: 1, col: 1 },
            end: Position { line: 1, col: 1 },
        })
        .group_by(|v| v.rule_index)
        .into_iter()
        .map(|(k, vals)| SecretResult {
            rule_id: sds_rules[k].clone().id,
            filename: filename.to_string(),
            message: sds_rules[k].clone().description,
            matches: vals
                .map(|v| SecretResultMatch {
                    start: v.start,
                    end: v.end,
                })
                .collect(),
        })
        .collect()
}
