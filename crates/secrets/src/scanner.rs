// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::model::secret_result::{SecretResult, SecretResultMatch, SecretValidationStatus};
use crate::model::secret_rule::SecretRule;
use anyhow::Error;
use common::analysis_options::AnalysisOptions;
use common::model::position::Position;
use common::utils::position_utils::get_position_in_string;
use dd_sds::{RootRuleConfig, RuleConfig, Scanner};
use itertools::Itertools;
use std::sync::Arc;

/// Build the SDS scanner used to scan all code using the rules fetched from
/// our API.
///
/// Once the scanner is built, use scanner.scan() to find secrets.
pub fn build_sds_scanner(rules: &[SecretRule], use_debug: bool) -> Scanner {
    let sds_rules = rules
        .iter()
        .map(|r| r.convert_to_sds_ruleconfig(use_debug).into_dyn())
        .collect::<Vec<RootRuleConfig<Arc<dyn RuleConfig>>>>();
    Scanner::builder(&sds_rules)
        .with_return_matches(true)
        .build()
        .expect("error when instantiating the scanner")
}

/// Find secrets in code. This is the main entrypoint for our SDS integration.
pub fn find_secrets(
    scanner: &Scanner,
    sds_rules: &[SecretRule],
    filename: &str,
    code: &str,
    options: &AnalysisOptions,
) -> Vec<SecretResult> {
    struct Result {
        rule_index: usize,
        start: Position,
        end: Position,
        validation_status: SecretValidationStatus,
    }

    let mut codemut = code.to_owned();
    let mut matches = match scanner.scan(&mut codemut) {
        Ok(matches) => matches,
        Err(err) => {
            if options.use_debug {
                eprintln!("error when scanning secrets for filename {}: {:?}", filename, err);
            }
            return vec![];
        }
    };

    if matches.is_empty() {
        return vec![];
    }

    let matches_validation = scanner.validate_matches(&mut matches);

    if matches_validation.is_err() && options.use_debug {
        eprintln!("error when validating secrets for filename {}", filename)
    }

    matches
        .iter()
        .flat_map(|sds_match| {
            let start = get_position_in_string(code, sds_match.start_index)?;
            let end = get_position_in_string(code, sds_match.end_index_exclusive)?;

            Ok::<Result, Error>(Result {
                rule_index: sds_match.rule_index,
                start,
                end,
                validation_status: SecretValidationStatus::from(&sds_match.match_status),
            })
        })
        .chunk_by(|v| v.rule_index)
        .into_iter()
        .map(|(k, vals)| SecretResult {
            rule_id: sds_rules[k].clone().id,
            rule_name: sds_rules[k].clone().name,
            filename: filename.to_string(),
            // there is no message for secret rules like we do with the static analyzer.
            // we are putting the rule name instead. Update this if you want to change
            // and put more context.
            message: sds_rules[k].clone().name,
            matches: vals
                .map(|v| SecretResultMatch {
                    start: v.start,
                    end: v.end,
                    validation_status: v.validation_status,
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

    #[test]
    fn test_find_secrets() {
        let rules: Vec<SecretRule> = vec![SecretRule {
            id: "secret_rule".to_string(),
            sds_id: "sds_id".to_string(),
            name: "detect a lot of secrets!".to_string(),
            description: "super secret!".to_string(),
            pattern: "FOO(BAR|BAZ)".to_string(),
            default_included_keywords: vec![],
            validators: Some(vec![]),
            match_validation: None,
        }];
        let scanner = build_sds_scanner(rules.as_slice(), false);
        let text = "FOO\nFOOBAR\nFOOBAZ\nCAT";
        let matches = find_secrets(
            &scanner,
            rules.as_slice(),
            "myfile",
            text,
            &AnalysisOptions::default(),
        );

        assert_eq!(matches.first().unwrap().matches.len(), 2);
        assert_eq!(
            matches.first().unwrap().matches.get(0).unwrap().start,
            Position { line: 2, col: 1 }
        );
        assert_eq!(
            matches.first().unwrap().matches.get(0).unwrap().end,
            Position { line: 2, col: 7 }
        );
        assert_eq!(
            matches.first().unwrap().matches.get(1).unwrap().start,
            Position { line: 3, col: 1 }
        );
        assert_eq!(
            matches.first().unwrap().matches.get(1).unwrap().end,
            Position { line: 3, col: 7 }
        );
    }
}
