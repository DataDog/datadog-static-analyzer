// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::file_mgmt::get_lines_to_ignore;
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
pub fn build_sds_scanner(rules: &[SecretRule], use_debug: bool) -> Result<Scanner, String> {
    let sds_rules = rules
        .iter()
        .map(|r| r.convert_to_sds_ruleconfig(use_debug).into_dyn())
        .collect::<Vec<RootRuleConfig<Arc<dyn RuleConfig>>>>();
    Scanner::builder(&sds_rules)
        .with_return_matches(true)
        .build()
        .map_err(|e| format!("Failed to build scanner: {e}"))
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

    // Get lines to ignore based on no-dd-secrets directives
    let lines_to_ignore = get_lines_to_ignore(code);

    let mut codemut = code.to_owned();
    let mut matches = match scanner.scan(&mut codemut) {
        Ok(m) => m,
        Err(e) => {
            if options.use_debug {
                eprintln!(
                    "error when scanning for secrets in filename {}: {}",
                    filename, e
                );
            }
            return vec![];
        }
    };

    if matches.is_empty() {
        return vec![];
    }

    if !options.disable_validation {
        scanner.validate_matches(&mut matches);
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
            priority: sds_rules[k].priority,
            // there is no message for secret rules like we do with the static analyzer.
            // we are putting the rule name instead. Update this if you want to change
            // and put more context.
            message: sds_rules[k].clone().name,
            matches: vals
                .map(|v| SecretResultMatch {
                    is_suppressed: lines_to_ignore.contains(&v.start.line),
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
    use crate::model::secret_rule::RulePriority;

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
            default_excluded_keywords: vec![],
            look_ahead_character_count: Some(30),
            priority: RulePriority::Medium,
            validators: Some(vec![]),
            validators_v2: None,
            match_validation: None,
            pattern_capture_groups: vec![],
        }];
        let scanner = build_sds_scanner(rules.as_slice(), false).expect("error building scanner");
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
            matches.first().unwrap().matches.first().unwrap().start,
            Position { line: 2, col: 1 }
        );
        assert_eq!(
            matches.first().unwrap().matches.first().unwrap().end,
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

    #[test]
    fn test_find_secrets_with_ignore_directive() {
        let rules: Vec<SecretRule> = vec![SecretRule {
            id: "secret_rule".to_string(),
            sds_id: "sds_id".to_string(),
            name: "detect secrets".to_string(),
            description: "super secret!".to_string(),
            pattern: "FOO(BAR|BAZ)".to_string(),
            default_included_keywords: vec![],
            default_excluded_keywords: vec![],
            look_ahead_character_count: Some(30),
            priority: RulePriority::Medium,
            validators: Some(vec![]),
            validators_v2: None,
            match_validation: None,
            pattern_capture_groups: vec![],
        }];
        let scanner = build_sds_scanner(rules.as_slice(), false).expect("error building scanner");
        // Line 1: FOOBAR - should be found
        // Line 2: #no-dd-secrets
        // Line 3: FOOBAZ - should be ignored
        let text = "FOOBAR\n#no-dd-secrets\nFOOBAZ";
        let matches = find_secrets(
            &scanner,
            rules.as_slice(),
            "myfile",
            text,
            &AnalysisOptions::default(),
        );

        // FOOBAR at line 1 is found and not suppressed (directive on line 2 covers line 3)
        assert_eq!(matches.len(), 1);
        assert_eq!(matches.first().unwrap().matches.len(), 1);
        let first = matches.first().unwrap().matches.first().unwrap();
        assert_eq!(first.start, Position { line: 1, col: 1 });
        assert!(!first.is_suppressed);
    }

    #[test]
    fn test_find_secrets_with_multiple_ignore_directives() {
        let rules: Vec<SecretRule> = vec![SecretRule {
            id: "secret_rule".to_string(),
            sds_id: "sds_id".to_string(),
            name: "detect secrets".to_string(),
            description: "super secret!".to_string(),
            pattern: "FOO(BAR|BAZ)".to_string(),
            default_included_keywords: vec![],
            default_excluded_keywords: vec![],
            look_ahead_character_count: Some(30),
            priority: RulePriority::Medium,
            validators: Some(vec![]),
            validators_v2: None,
            match_validation: None,
            pattern_capture_groups: vec![],
        }];
        let scanner = build_sds_scanner(rules.as_slice(), false).expect("error building scanner");
        // Line 1: FOOBAR - should be found
        // Line 2: #no-dd-secrets
        // Line 3: FOOBAZ - should be ignored
        // Line 4: FOOBAR - should be found
        // Line 5: //no-dd-secrets
        // Line 6: FOOBAZ - should be ignored
        let text = "FOOBAR\n#no-dd-secrets\nFOOBAZ\nFOOBAR\n//no-dd-secrets\nFOOBAZ\n";
        let matches = find_secrets(
            &scanner,
            rules.as_slice(),
            "myfile",
            text,
            &AnalysisOptions::default(),
        );

        // 3 matches total: FOOBAR(line 1) and FOOBAR(line 4) are not suppressed;
        // one FOOBAZ match (line 3 or 6) is suppressed
        assert_eq!(matches.len(), 1);
        let result_matches = &matches.first().unwrap().matches;
        assert_eq!(result_matches.len(), 4);
        let line1 = result_matches.iter().find(|m| m.start.line == 1).unwrap();
        assert!(!line1.is_suppressed);
        let line2 = result_matches.iter().find(|m| m.start.line == 3).unwrap();
        assert!(line2.is_suppressed);
        let line4 = result_matches.iter().find(|m| m.start.line == 4).unwrap();
        assert!(!line4.is_suppressed);
        let line6 = result_matches.iter().find(|m| m.start.line == 6).unwrap();
        assert!(line6.is_suppressed);
    }

    #[test]
    fn test_find_secrets_all_ignored() {
        let rules: Vec<SecretRule> = vec![SecretRule {
            id: "secret_rule".to_string(),
            sds_id: "sds_id".to_string(),
            name: "detect secrets".to_string(),
            description: "super secret!".to_string(),
            pattern: "FOO(BAR|BAZ)".to_string(),
            default_included_keywords: vec![],
            default_excluded_keywords: vec![],
            look_ahead_character_count: Some(30),
            priority: RulePriority::Medium,
            validators: Some(vec![]),
            validators_v2: None,
            match_validation: None,
            pattern_capture_groups: vec![],
        }];
        let scanner = build_sds_scanner(rules.as_slice(), false).expect("error building scanner");
        // Directive on line 1 means ignore entire file
        let text = "#no-dd-secrets\nFOOBAR\nFOOBAZ";
        let matches = find_secrets(
            &scanner,
            rules.as_slice(),
            "myfile",
            text,
            &AnalysisOptions::default(),
        );

        // FOOBAR at line 2 is found and suppressed (directive on line 1 covers line 2)
        assert_eq!(matches.len(), 1);
        assert_eq!(matches.first().unwrap().matches.len(), 1);
        let first = matches.first().unwrap().matches.first().unwrap();
        assert_eq!(first.start, Position { line: 2, col: 1 });
        assert!(first.is_suppressed);
    }
}
