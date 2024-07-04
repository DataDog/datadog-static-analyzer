// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::model::secret_result::{SecretResult, SecretResultMatch};
use crate::model::secret_rule::SecretRule;
use anyhow::anyhow;
use common::analysis_options::AnalysisOptions;
use common::model::position::Position;
use itertools::Itertools;
use sds::{RuleConfig, Scanner};

/// Build the SDS scanner used to scan all code using the rules fetched from
/// our API.
///
/// Once the scanner is built, use scanner.scan() to find secrets.
pub fn build_sds_scanner(rules: &[SecretRule]) -> Scanner {
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

/// Get position of an offset in a code and return a [[Position]]. This code should
/// ultimately be more efficient as we grow the platform, it's considered as "good enough" for now.
pub fn get_position_in_string(content: &str, offset: usize) -> anyhow::Result<Position> {
    let mut line_number = 1;
    let mut bytes_reads = 0;

    for line in content.lines() {
        if offset >= bytes_reads && offset <= bytes_reads + line.len() {
            let c = offset - bytes_reads + 1;
            return Ok(Position {
                line: line_number,
                col: c as u32,
            });
        }
        line_number += 1;
        bytes_reads = bytes_reads + line.len() + 1;
    }
    Err(anyhow!("line not found"))
}

/// Find secrets in code. This is the main entrypoint for our SDS integration.
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
            start: get_position_in_string(code, sds_match.start_index)
                .expect("cannot get position"),
            end: get_position_in_string(code, sds_match.end_index_exclusive)
                .expect("cannot get position"),
        })
        .group_by(|v| v.rule_index)
        .into_iter()
        .map(|(k, vals)| SecretResult {
            rule_id: sds_rules[k].clone().id,
            rule_name: sds_rules[k].clone().name,
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

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_get_position_in_string() {
        let s = "FOO\nBAR\nBAZ";
        let p1 = get_position_in_string(s, 0).expect("get the pos");
        assert_eq!(1, p1.line);
        assert_eq!(1, p1.col);

        let p2 = get_position_in_string(s, 4).expect("get the pos");
        assert_eq!(2, p2.line);
        assert_eq!(1, p2.col);

        assert!(get_position_in_string(s, 40000).is_err());
    }
}
