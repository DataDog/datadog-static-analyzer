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
use dd_sds::{RootRuleConfig, RuleConfig, ScanOptionBuilder, Scanner};
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

    let scan_options = ScanOptionBuilder::new()
        .with_validate_matching(!options.disable_validation)
        .build();

    let matches = match scanner.scan_with_options(&mut codemut, scan_options) {
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
    use crate::model::secret_result::SecretValidationStatus;
    use crate::model::secret_rule::{
        RulePriority, SecretRuleHttpCallConfig, SecretRuleHttpRequestConfig,
        SecretRuleHttpResponseConfig, SecretRuleMatchPairingConfig, SecretRuleMatchValidation,
        SecretRuleMatchValidationHttpMethod, SecretRuleMatchValidationHttpV2,
        SecretRulePairedValidatorConfig, SecretRuleResponseCondition,
        SecretRuleResponseConditionType, SecretRuleStatusCodeMatcher,
    };

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
            is_supporting_rule: false,
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
    fn test_find_secrets_discards_supporting_rule_matches() {
        let supporting_rule = SecretRule {
            id: "supporting".to_string(),
            sds_id: "sds_id_supporting".to_string(),
            name: "supporting".to_string(),
            description: "supporting".to_string(),
            pattern: "FOOBAR".to_string(),
            default_included_keywords: vec![],
            default_excluded_keywords: vec![],
            look_ahead_character_count: Some(30),
            priority: RulePriority::Medium,
            validators: Some(vec![]),
            validators_v2: None,
            match_validation: None,
            pattern_capture_groups: vec![],
            is_supporting_rule: true,
        };
        let primary_rule = SecretRule {
            id: "primary".to_string(),
            sds_id: "sds_id_primary".to_string(),
            name: "primary".to_string(),
            description: "primary".to_string(),
            pattern: "FOOBAZ".to_string(),
            default_included_keywords: vec![],
            default_excluded_keywords: vec![],
            look_ahead_character_count: Some(30),
            priority: RulePriority::Medium,
            validators: Some(vec![]),
            validators_v2: None,
            match_validation: None,
            pattern_capture_groups: vec![],
            is_supporting_rule: false,
        };

        let rules = vec![supporting_rule, primary_rule];
        let scanner = build_sds_scanner(rules.as_slice(), false).expect("error building scanner");
        let text = "FOOBAR\nFOOBAZ\n";

        let results = find_secrets(
            &scanner,
            rules.as_slice(),
            "myfile",
            text,
            &AnalysisOptions::default(),
        );

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].rule_id, "primary");
        assert_eq!(results[0].matches.len(), 1);
    }

    #[test]
    fn test_find_secrets_only_supporting_rule_returns_no_results() {
        let rules: Vec<SecretRule> = vec![SecretRule {
            id: "supporting".to_string(),
            sds_id: "sds_id_supporting".to_string(),
            name: "supporting".to_string(),
            description: "supporting".to_string(),
            pattern: "FOOBAR".to_string(),
            default_included_keywords: vec![],
            default_excluded_keywords: vec![],
            look_ahead_character_count: Some(30),
            priority: RulePriority::Medium,
            validators: Some(vec![]),
            validators_v2: None,
            match_validation: None,
            pattern_capture_groups: vec![],
            is_supporting_rule: true,
        }];

        let scanner = build_sds_scanner(rules.as_slice(), false).expect("error building scanner");
        let text = "FOOBAR\n";
        let results = find_secrets(
            &scanner,
            rules.as_slice(),
            "myfile",
            text,
            &AnalysisOptions::default(),
        );

        assert!(results.is_empty());
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
            is_supporting_rule: false,
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
            is_supporting_rule: false,
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
    fn test_find_secrets_disable_validation() {
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
            is_supporting_rule: false,
        }];
        let scanner = build_sds_scanner(rules.as_slice(), false).expect("error building scanner");
        let text = "FOO\nFOOBAR\nFOOBAZ\nCAT";

        let options = AnalysisOptions {
            disable_validation: true,
            ..Default::default()
        };
        let matches = find_secrets(&scanner, rules.as_slice(), "myfile", text, &options);

        assert_eq!(matches.len(), 1);
        let result_matches = &matches.first().unwrap().matches;
        assert_eq!(result_matches.len(), 2);
        for m in result_matches {
            assert_eq!(m.validation_status, SecretValidationStatus::NotAvailable);
        }
    }

    /// A supporting rule's match must be excluded from `find_secrets` output, but its value
    /// must still be used to populate template variables for the main rule's HTTP validation call.
    #[test]
    fn test_supporting_rule_excluded_from_output_but_used_for_match_pairing() {
        use httpmock::Method::GET;
        use httpmock::MockServer;
        use std::collections::BTreeMap;

        let server = MockServer::start();

        let mock = server.mock(|when, then| {
            when.method(GET)
                .path("/validate")
                .query_param("secret", "api_key_abc123")
                .query_param("subdomain", "acme_corp");
            then.status(200);
        });

        let supporting_rule = SecretRule {
            id: "supporting".to_string(),
            sds_id: "sds_id_supporting".to_string(),
            name: "supporting".to_string(),
            description: "supporting".to_string(),
            pattern: "\\b[a-z_]+_corp\\b".to_string(),
            default_included_keywords: vec![],
            default_excluded_keywords: vec![],
            look_ahead_character_count: Some(30),
            priority: RulePriority::Medium,
            validators: Some(vec![]),
            validators_v2: None,
            match_validation: Some(SecretRuleMatchValidation::CustomHttpV2(
                SecretRuleMatchValidationHttpV2 {
                    provides: Some(vec![SecretRulePairedValidatorConfig {
                        kind: "vendor_xyz".to_string(),
                        name: "client_subdomain".to_string(),
                    }]),
                    calls: vec![],
                    match_pairing: None,
                },
            )),
            pattern_capture_groups: vec![],
            is_supporting_rule: true,
        };

        let mut parameters = BTreeMap::new();
        parameters.insert("client_subdomain".to_string(), "$SUBDOMAIN".to_string());

        let primary_rule = SecretRule {
            id: "primary".to_string(),
            sds_id: "sds_id_primary".to_string(),
            name: "primary".to_string(),
            description: "primary".to_string(),
            pattern: "\\bapi_key_[a-z0-9]+\\b".to_string(),
            default_included_keywords: vec![],
            default_excluded_keywords: vec![],
            look_ahead_character_count: Some(30),
            priority: RulePriority::Medium,
            validators: Some(vec![]),
            validators_v2: None,
            match_validation: Some(SecretRuleMatchValidation::CustomHttpV2(
                SecretRuleMatchValidationHttpV2 {
                    match_pairing: Some(SecretRuleMatchPairingConfig {
                        kind: "vendor_xyz".to_string(),
                        parameters,
                    }),
                    provides: None,
                    calls: vec![SecretRuleHttpCallConfig {
                        request: SecretRuleHttpRequestConfig {
                            endpoint: format!(
                                "{}/validate?secret=$MATCH&subdomain=$SUBDOMAIN",
                                server.base_url()
                            ),
                            method: SecretRuleMatchValidationHttpMethod::Get,
                            hosts: vec![],
                            headers: BTreeMap::new(),
                            body: None,
                            timeout_seconds: Some(3),
                        },
                        response: SecretRuleHttpResponseConfig {
                            conditions: vec![SecretRuleResponseCondition {
                                condition_type: SecretRuleResponseConditionType::Valid,
                                status_code: Some(SecretRuleStatusCodeMatcher::Single {
                                    single: 200,
                                }),
                                raw_body: None,
                                body: None,
                            }],
                        },
                    }],
                },
            )),
            pattern_capture_groups: vec![],
            is_supporting_rule: false,
        };

        let rules = vec![supporting_rule, primary_rule];
        let scanner = build_sds_scanner(rules.as_slice(), false).expect("error building scanner");

        let results = find_secrets(
            &scanner,
            rules.as_slice(),
            "myfile",
            "subdomain: acme_corp, key: api_key_abc123\n",
            &AnalysisOptions::default(),
        );

        // The supporting rule match must not appear in output
        assert!(
            results.iter().all(|r| r.rule_id != "supporting"),
            "supporting rule should not appear in output"
        );

        // The main rule match must appear with Valid status
        let main_result = results
            .iter()
            .find(|r| r.rule_id == "primary")
            .expect("main rule should have a match");
        assert_eq!(main_result.matches.len(), 1);
        assert_eq!(
            main_result.matches[0].validation_status,
            SecretValidationStatus::Valid
        );

        // The HTTP mock was called, proving the template variable was resolved from the
        // supporting rule's match even though that match is not in the output
        mock.assert();
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
            is_supporting_rule: false,
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
