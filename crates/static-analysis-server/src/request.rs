use crate::constants::{
    ERROR_CHECKSUM_MISMATCH, ERROR_CODE_LANGUAGE_MISMATCH, ERROR_CODE_NOT_BASE64,
    ERROR_CONFIGURATION_NOT_BASE64, ERROR_COULD_NOT_PARSE_CONFIGURATION, ERROR_DECODING_BASE64,
};
use crate::model::analysis_request::{AnalysisRequest, ServerRule};
use crate::model::analysis_response::{AnalysisResponse, RuleResponse};
use crate::model::violation::violation_to_server;
use kernel::analysis::analyze::analyze;
use kernel::config_file::parse_config_file;
use kernel::model::analysis::AnalysisOptions;
use kernel::model::rule::{Rule, RuleCategory, RuleInternal, RuleSeverity};
use kernel::path_restrictions::is_allowed_by_path_config;
use kernel::rule_config::RulesConfigProvider;
use kernel::utils::decode_base64_string;

#[tracing::instrument(skip_all)]
pub fn process_analysis_request(request: AnalysisRequest) -> AnalysisResponse {
    tracing::debug!("Processing analysis request");

    // Decode the configuration, if present.
    let configuration = match request.configuration_base64.map(decode_base64_string) {
        Some(Err(_)) => {
            tracing::info!("Validation error: configuration is not a base64 string");
            return AnalysisResponse {
                rule_responses: vec![],
                errors: vec![ERROR_CONFIGURATION_NOT_BASE64.to_string()],
            };
        }
        Some(Ok(cfg)) => match parse_config_file(&cfg) {
            Err(_) => {
                tracing::info!("Validation error: could not parse configuration");
                return AnalysisResponse {
                    rule_responses: vec![],
                    errors: vec![ERROR_COULD_NOT_PARSE_CONFIGURATION.to_string()],
                };
            }
            Ok(cfg_file) => Some(cfg_file),
        },
        None => None,
    };

    // If the file is excluded by the global configuration, stop early.
    let file_is_excluded_by_cfg = configuration
        .as_ref()
        .map(|cfg_file| !is_allowed_by_path_config(&cfg_file.paths, &request.filename))
        .unwrap_or_default();
    if file_is_excluded_by_cfg {
        tracing::debug!("Skipped excluded file: {}", request.filename);
        return AnalysisResponse {
            rule_responses: vec![],
            errors: vec![],
        };
    }

    // Extract the rule configurations from the configuration file.
    let rules_config_provider = configuration
        .as_ref()
        .map(RulesConfigProvider::from_config)
        .unwrap_or_default();
    let rules_config = rules_config_provider.for_file(&request.filename);

    let rules_with_invalid_language: Vec<ServerRule> = request
        .rules
        .iter()
        .filter(|&v| v.language != request.language)
        .cloned()
        .collect();
    if !rules_with_invalid_language.is_empty() {
        for rule in rules_with_invalid_language {
            tracing::info!(
                "Validation error: request language is `{}`, but rule `{}` language is `{}`",
                request.language,
                &rule.name,
                rule.language
            );
        }
        return AnalysisResponse {
            rule_responses: vec![],
            errors: vec![ERROR_CODE_LANGUAGE_MISMATCH.to_string()],
        };
    }

    let server_rules_to_rules: Vec<Rule> = request
        .rules
        .iter()
        .filter(|r| rules_config.is_rule_enabled(&r.name))
        .map(|r| Rule {
            name: r.name.clone(),
            short_description_base64: r.short_description_base64.clone(),
            description_base64: r.description_base64.clone(),
            category: r.category.unwrap_or(RuleCategory::BestPractices),
            severity: r.severity.unwrap_or(RuleSeverity::Warning),
            language: r.language,
            rule_type: r.rule_type,
            cwe: None,
            entity_checked: r.entity_checked,
            code_base64: r.code_base64.clone(),
            checksum: r.checksum.clone().unwrap_or("".to_string()),
            pattern: r.pattern.clone(),
            tree_sitter_query_base64: r.tree_sitter_query_base64.clone(),
            arguments: r.arguments.clone(),
            tests: vec![],
            is_testing: false,
        })
        .collect();

    if server_rules_to_rules.is_empty() {
        tracing::info!("Successfully completed analysis for 0 rules");
        return AnalysisResponse {
            rule_responses: vec![],
            errors: vec![],
        };
    }

    // Convert the rules from the server into internal rules
    let rules: Result<Vec<RuleInternal>, anyhow::Error> = server_rules_to_rules
        .iter()
        .map(|r| {
            let rule_internal = r.to_rule_internal();
            if let Err(err) = &rule_internal {
                tracing::info!(
                    "Validation error: request rule could not be parsed (reason: {})",
                    err
                )
            }
            rule_internal
        })
        .collect::<Result<Vec<RuleInternal>, anyhow::Error>>();
    let Ok(rules) = rules else {
        return AnalysisResponse {
            rule_responses: vec![],
            errors: vec![ERROR_DECODING_BASE64.to_string()],
        };
    };

    // let's try to decode the code
    let code_decoded_attempt = decode_base64_string(request.code_base64);
    if code_decoded_attempt.is_err() {
        tracing::info!("Validation error: code is not a base64 string");
        return AnalysisResponse {
            rule_responses: vec![],
            errors: vec![ERROR_CODE_NOT_BASE64.to_string()],
        };
    }

    // We check each rule and if the checksum is correct or not. If one rule does not
    // have a valid checksum, we return an error.
    for rule in &server_rules_to_rules {
        if !rule.verify_checksum() {
            tracing::info!(
                "Validation error: request rule `{}` has invalid checksum",
                rule.name
            );
            return AnalysisResponse {
                rule_responses: vec![],
                errors: vec![ERROR_CHECKSUM_MISMATCH.to_string()],
            };
        }
    }

    let rules_count = rules.len();
    let rules_str = if rules_count == 1 { "rule" } else { "rules" };
    let rules_list = rules
        .iter()
        .map(|r| r.name.as_str())
        .collect::<Vec<&str>>()
        .join(", ");
    // execute the rule. If we fail to convert, return an error.
    let rule_results = analyze(
        &request.language,
        &rules,
        &request.filename,
        code_decoded_attempt.unwrap().as_str(),
        &rules_config,
        &AnalysisOptions {
            use_debug: false,
            log_output: request
                .options
                .map(|o| o.log_output.unwrap_or(false))
                .unwrap_or(false),
            ignore_generated_files: false,
        },
    );

    let rule_responses = rule_results
        .iter()
        .map(|rr| RuleResponse {
            identifier: rr.rule_name.clone(),
            violations: rr.violations.iter().map(violation_to_server).collect(),
            errors: rr.errors.clone(),
            execution_error: rr.execution_error.clone(),
            output: rr.output.clone(),
            execution_time_ms: rr.execution_time_ms,
        })
        .collect();

    tracing::info!(
        "Successfully completed analysis for {} {} ({})",
        rules_count,
        rules_str,
        rules_list
    );
    AnalysisResponse {
        rule_responses,
        errors: vec![],
    }
}

#[cfg(test)]
mod tests {
    use crate::model::analysis_request::ServerRule;
    use kernel::model::{
        common::Language,
        rule::{RuleCategory, RuleSeverity, RuleType},
    };
    use kernel::utils::encode_base64_string;

    use super::*;

    #[test]
    fn test_request_correct_response() {
        let request = AnalysisRequest {
            filename: "myfile.py".to_string(),
            language: Language::Python,
            file_encoding: "utf-8".to_string(),
            code_base64: "ZGVmIGZvbyhhcmcxKToKICAgIHBhc3M=".to_string(),
            configuration_base64: None,
            options: None,
            rules: vec![
                ServerRule{
                    name: "myrule".to_string(),
                    short_description_base64: None,
                    description_base64: None,
                    category: Some(RuleCategory::BestPractices),
                    severity: Some(RuleSeverity::Warning),
                    language: Language::Python,
                    rule_type: RuleType::TreeSitterQuery,
                    entity_checked: None,
                    code_base64: "ZnVuY3Rpb24gdmlzaXQobm9kZSwgZmlsZW5hbWUsIGNvZGUpIHsKICAgIGNvbnN0IGZ1bmN0aW9uTmFtZSA9IG5vZGUuY2FwdHVyZXNbIm5hbWUiXTsKICAgIGlmKGZ1bmN0aW9uTmFtZSkgewogICAgICAgIGNvbnN0IGVycm9yID0gYnVpbGRFcnJvcihmdW5jdGlvbk5hbWUuc3RhcnQubGluZSwgZnVuY3Rpb25OYW1lLnN0YXJ0LmNvbCwgZnVuY3Rpb25OYW1lLmVuZC5saW5lLCBmdW5jdGlvbk5hbWUuZW5kLmNvbCwKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgImludmFsaWQgbmFtZSIsICJDUklUSUNBTCIsICJzZWN1cml0eSIpOwoKICAgICAgICBjb25zdCBlZGl0ID0gYnVpbGRFZGl0KGZ1bmN0aW9uTmFtZS5zdGFydC5saW5lLCBmdW5jdGlvbk5hbWUuc3RhcnQuY29sLCBmdW5jdGlvbk5hbWUuZW5kLmxpbmUsIGZ1bmN0aW9uTmFtZS5lbmQuY29sLCAidXBkYXRlIiwgImJhciIpOwogICAgICAgIGNvbnN0IGZpeCA9IGJ1aWxkRml4KCJ1c2UgYmFyIiwgW2VkaXRdKTsKICAgICAgICBhZGRFcnJvcihlcnJvci5hZGRGaXgoZml4KSk7CiAgICB9Cn0=".to_string(),
                    checksum: Some("f546e49732dc071fd5da82e1a2d9bcf5cf9a824c3679d8b59237c4ba23340057".to_string()),
                    pattern: None,
                    tree_sitter_query_base64: Some("KGZ1bmN0aW9uX2RlZmluaXRpb24KICAgIG5hbWU6IChpZGVudGlmaWVyKSBAbmFtZQogIHBhcmFtZXRlcnM6IChwYXJhbWV0ZXJzKSBAcGFyYW1zCik=".to_string()),
                    arguments: vec![],
                }
            ]
        };
        let response = process_analysis_request(request);
        assert!(response.errors.is_empty());
        assert_eq!(1, response.rule_responses.len());
        assert_eq!(1, response.rule_responses.get(0).unwrap().violations.len());
    }

    #[test]
    fn test_invalid_checksum() {
        let request = AnalysisRequest {
            filename: "myfile.py".to_string(),
            language: Language::Python,
            file_encoding: "utf-8".to_string(),
            code_base64: "ZGVmIGZvbyhhcmcxKToKICAgIHBhc3M=".to_string(),
            configuration_base64: None,
            options: None,
            rules: vec![
                ServerRule{
                    name: "myrule".to_string(),
                    short_description_base64: None,
                    description_base64: None,
                    category: Some(RuleCategory::BestPractices),
                    severity: Some(RuleSeverity::Warning),
                    language: Language::Python,
                    rule_type: RuleType::TreeSitterQuery,
                    entity_checked: None,
                    code_base64: "ZnVuY3Rpb24gdmlzaXQobm9kZSwgZmlsZW5hbWUsIGNvZGUpIHsKICAgIGNvbnN0IGZ1bmN0aW9uTmFtZSA9IG5vZGUuY2FwdHVyZXNbIm5hbWUiXTsKICAgIGlmKGZ1bmN0aW9uTmFtZSkgewogICAgICAgIGNvbnN0IGVycm9yID0gYnVpbGRFcnJvcihmdW5jdGlvbk5hbWUuc3RhcnQubGluZSwgZnVuY3Rpb25OYW1lLnN0YXJ0LmNvbCwgZnVuY3Rpb25OYW1lLmVuZC5saW5lLCBmdW5jdGlvbk5hbWUuZW5kLmNvbCwKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgImludmFsaWQgbmFtZSIsICJDUklUSUNBTCIsICJzZWN1cml0eSIpOwoKICAgICAgICBjb25zdCBlZGl0ID0gYnVpbGRFZGl0KGZ1bmN0aW9uTmFtZS5zdGFydC5saW5lLCBmdW5jdGlvbk5hbWUuc3RhcnQuY29sLCBmdW5jdGlvbk5hbWUuZW5kLmxpbmUsIGZ1bmN0aW9uTmFtZS5lbmQuY29sLCAidXBkYXRlIiwgImJhciIpOwogICAgICAgIGNvbnN0IGZpeCA9IGJ1aWxkRml4KCJ1c2UgYmFyIiwgW2VkaXRdKTsKICAgICAgICBhZGRFcnJvcihlcnJvci5hZGRGaXgoZml4KSk7CiAgICB9Cn0=".to_string(),
                    checksum: Some("f546e49732dc071fd5da82e1a2d9bcf5cf9a824c36d8b59237c4ba23340057".to_string()),
                    pattern: None,
                    tree_sitter_query_base64: Some("KGZ1bmN0aW9uX2RlZmluaXRpb24KICAgIG5hbWU6IChpZGVudGlmaWVyKSBAbmFtZQogIHBhcmFtZXRlcnM6IChwYXJhbWV0ZXJzKSBAcGFyYW1zCik=".to_string()),
                    arguments: vec![],
                }
            ]
        };
        let response = process_analysis_request(request);
        assert_eq!(0, response.rule_responses.len());
        assert_eq!(
            &ERROR_CHECKSUM_MISMATCH.to_string(),
            response.errors.get(0).unwrap()
        );
    }

    #[test]
    fn test_request_invalid_base64() {
        let request = AnalysisRequest {
            filename: "myfile.py".to_string(),
            language: Language::Python,
            file_encoding: "utf-8".to_string(),
            code_base64: "ZGVmIGZvbyhhcmcxKToKI()--2#$#$Bhc3M=".to_string(),
            configuration_base64: None,
            options: None,
            rules: vec![
                ServerRule{
                    name: "myrule".to_string(),
                    short_description_base64: None,
                    description_base64: None,
                    category: None,
                    severity: None,
                    language: Language::Python,
                    rule_type: RuleType::TreeSitterQuery,
                    entity_checked: None,
                    code_base64: "ZnVuY3Rpb24gdmlzaXQobm9kZSwgZmlsZW5hbWUsIGNvZGUpIHsKICAgIGNvbnN0IGZ1bmN0aW9uTmFtZSA9IG5vZGUuY2FwdHVyZXNbIm5hbWUiXTsKICAgIGlmKGZ1bmN0aW9uTmFtZSkgewogICAgICAgIGNvbnN0IGVycm9yID0gYnVpbGRFcnJvcihmdW5jdGlvbk5hbWUuc3RhcnQubGluZSwgZnVuY3Rpb25OYW1lLnN0YXJ0LmNvbCwgZnVuY3Rpb25OYW1lLmVuZC5saW5lLCBmdW5jdGlvbk5hbWUuZW5kLmNvbCwKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgImludmFsaWQgbmFtZSIsICJDUklUSUNBTCIsICJzZWN1cml0eSIpOwoKICAgICAgICBjb25zdCBlZGl0ID0gYnVpbGRFZGl0KGZ1bmN0aW9uTmFtZS5zdGFydC5saW5lLCBmdW5jdGlvbk5hbWUuc3RhcnQuY29sLCBmdW5jdGlvbk5hbWUuZW5kLmxpbmUsIGZ1bmN0aW9uTmFtZS5lbmQuY29sLCAidXBkYXRlIiwgImJhciIpOwogICAgICAgIGNvbnN0IGZpeCA9IGJ1aWxkRml4KCJ1c2UgYmFyIiwgW2VkaXRdKTsKICAgICAgICBhZGRFcnJvcihlcnJvci5hZGRGaXgoZml4KSk7CiAgICB9Cn0=".to_string(),
                    checksum: None,
                    pattern: None,
                    tree_sitter_query_base64: Some("KGZ1bmN0aW9uX2RlZmluaXRpb24KICAgIG5hbWU6IChpZGVudGlmaWVyKSBAbmFtZQogIHBhcmFtZXRlcnM6IChwYXJhbWV0ZXJzKSBAcGFyYW1zCik=".to_string()),
                    arguments: vec![],
                }
            ]
        };
        let response = process_analysis_request(request);
        assert_eq!(0, response.rule_responses.len());
        assert_eq!(
            &ERROR_CODE_NOT_BASE64.to_string(),
            response.errors.get(0).unwrap()
        );
    }

    #[test]
    fn test_request_invalid_rule_base64_encoding() {
        let request = AnalysisRequest {
            filename: "myfile.py".to_string(),
            language: Language::Python,
            file_encoding: "utf-8".to_string(),
            code_base64: "ZGVmIGZvbyhhcmcxKToKICAgIHBhc3M=".to_string(),
            configuration_base64: None,
            options: None,
            rules: vec![
                ServerRule{
                    name: "myrule".to_string(),
                    short_description_base64: None,
                    description_base64: None,
                    category: None,
                    severity: None,
                    language: Language::Python,
                    rule_type: RuleType::TreeSitterQuery,
                    entity_checked: None,
                    code_base64: "ZnVuY3Rpb24gd23223222mlzaXQobm9kZSwgZmlsZW5hbWUsIGNvZGUpIHsKICAgIGNvbnN0IGZ1bmN0aW9uTmFtZSA9IG5vZGUuY2FwdHVyZXNbIm5hbWUiXTsKICAgIGlmKGZ1bmN0aW9uTmFtZSkgewogICAgICAgIGNvbnN0IGVycm9yID0gYnVpbGRFcnJvcihmdW5jdGlvbk5hbWUuc3RhcnQubGluZSwgZnVuY3Rpb25OYW1lLnN0YXJ0LmNvbCwgZnVuY3Rpb25OYW1lLmVuZC5saW5lLCBmdW5jdGlvbk5hbWUuZW5kLmNvbCwKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgImludmFsaWQgbmFtZSIsICJDUklUSUNBTCIsICJzZWN1cml0eSIpOwoKICAgICAgICBjb25zdCBlZGl0ID0gYnVpbGRFZGl0KGZ1bmN0aW9uTmFtZS5zdGFydC5saW5lLCBmdW5jdGlvbk5hbWUuc3RhcnQuY29sLCBmdW5jdGlvbk5hbWUuZW5kLmxpbmUsIGZ1bmN0aW9uTmFtZS5lbmQuY29sLCAidXBkYXRlIiwgImJhciIpOwogICAgICAgIGNvbnN0IGZpeCA9IGJ1aWxkRml4KCJ1c2UgYmFyIiwgW2VkaXRdKTsKICAgICAgICBhZGRFcnJvcihlcnJvci5hZGRGaXgoZml4KSk7CiAgICB9Cn0=".to_string(),
                    checksum: Some("1a1dd51c47738a19b073a20ffc16c1eb816a4a6ed05ffaa53c19db0caf036c0c".to_string()),
                    pattern: None,
                    tree_sitter_query_base64: Some("KGZ1bmN0aW9uX2RlZmluaXRpb24KICAgIG5hbWU6IChpZGVudGlmaWVyKSBAbmFtZQogIHBhcmFtZXRlcnM6IChwYXJhbWV0ZXJzKSBAcGFyYW1zCik=".to_string()),
                    arguments: vec![],
                }
            ]
        };
        let response = process_analysis_request(request);
        assert_eq!(0, response.rule_responses.len());
        assert_eq!(
            &ERROR_DECODING_BASE64.to_string(),
            response.errors.get(0).unwrap()
        );
    }

    #[test]
    fn test_request_invalid_language() {
        let request = AnalysisRequest {
            filename: "myfile.py".to_string(),
            language: Language::Python,
            file_encoding: "utf-8".to_string(),
            code_base64: "ZGVmIGZvbyhhcmcxKToKICAgIHBhc3M=".to_string(),
            configuration_base64: None,
            options: None,
            rules: vec![
                ServerRule{
                    name: "myrule".to_string(),
                    short_description_base64: None,
                    description_base64: None,
                    category: None,
                    severity: None,
                    language: Language::JavaScript,
                    rule_type: RuleType::TreeSitterQuery,
                    entity_checked: None,
                    code_base64: "ZnVuY3Rpb24gd23223222mlzaXQobm9kZSwgZmlsZW5hbWUsIGNvZGUpIHsKICAgIGNvbnN0IGZ1bmN0aW9uTmFtZSA9IG5vZGUuY2FwdHVyZXNbIm5hbWUiXTsKICAgIGlmKGZ1bmN0aW9uTmFtZSkgewogICAgICAgIGNvbnN0IGVycm9yID0gYnVpbGRFcnJvcihmdW5jdGlvbk5hbWUuc3RhcnQubGluZSwgZnVuY3Rpb25OYW1lLnN0YXJ0LmNvbCwgZnVuY3Rpb25OYW1lLmVuZC5saW5lLCBmdW5jdGlvbk5hbWUuZW5kLmNvbCwKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgImludmFsaWQgbmFtZSIsICJDUklUSUNBTCIsICJzZWN1cml0eSIpOwoKICAgICAgICBjb25zdCBlZGl0ID0gYnVpbGRFZGl0KGZ1bmN0aW9uTmFtZS5zdGFydC5saW5lLCBmdW5jdGlvbk5hbWUuc3RhcnQuY29sLCBmdW5jdGlvbk5hbWUuZW5kLmxpbmUsIGZ1bmN0aW9uTmFtZS5lbmQuY29sLCAidXBkYXRlIiwgImJhciIpOwogICAgICAgIGNvbnN0IGZpeCA9IGJ1aWxkRml4KCJ1c2UgYmFyIiwgW2VkaXRdKTsKICAgICAgICBhZGRFcnJvcihlcnJvci5hZGRGaXgoZml4KSk7CiAgICB9Cn0=".to_string(),
                    checksum: None,
                    pattern: None,
                    tree_sitter_query_base64: Some("KGZ1bmN0aW9uX2RlZmluaXRpb24KICAgIG5hbWU6IChpZGVudGlmaWVyKSBAbmFtZQogIHBhcmFtZXRlcnM6IChwYXJhbWV0ZXJzKSBAcGFyYW1zCik=".to_string()),
                    arguments: vec![],
                }
            ]
        };
        let response = process_analysis_request(request);
        assert_eq!(0, response.rule_responses.len());
        assert_eq!(
            &ERROR_CODE_LANGUAGE_MISMATCH.to_string(),
            response.errors.get(0).unwrap()
        );
    }

    #[test]
    fn test_request_configuration_includes_excludes() {
        let base_rule = ServerRule {
            name: "myrule".to_string(),
            short_description_base64: None,
            description_base64: None,
            category: Some(RuleCategory::BestPractices),
            severity: Some(RuleSeverity::Warning),
            language: Language::Python,
            rule_type: RuleType::TreeSitterQuery,
            entity_checked: None,
            code_base64: "ZnVuY3Rpb24gdmlzaXQobm9kZSwgZmlsZW5hbWUsIGNvZGUpIHsKICAgIGNvbnN0IGZ1bmN0aW9uTmFtZSA9IG5vZGUuY2FwdHVyZXNbIm5hbWUiXTsKICAgIGlmKGZ1bmN0aW9uTmFtZSkgewogICAgICAgIGNvbnN0IGVycm9yID0gYnVpbGRFcnJvcihmdW5jdGlvbk5hbWUuc3RhcnQubGluZSwgZnVuY3Rpb25OYW1lLnN0YXJ0LmNvbCwgZnVuY3Rpb25OYW1lLmVuZC5saW5lLCBmdW5jdGlvbk5hbWUuZW5kLmNvbCwKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgImludmFsaWQgbmFtZSIsICJDUklUSUNBTCIsICJzZWN1cml0eSIpOwoKICAgICAgICBjb25zdCBlZGl0ID0gYnVpbGRFZGl0KGZ1bmN0aW9uTmFtZS5zdGFydC5saW5lLCBmdW5jdGlvbk5hbWUuc3RhcnQuY29sLCBmdW5jdGlvbk5hbWUuZW5kLmxpbmUsIGZ1bmN0aW9uTmFtZS5lbmQuY29sLCAidXBkYXRlIiwgImJhciIpOwogICAgICAgIGNvbnN0IGZpeCA9IGJ1aWxkRml4KCJ1c2UgYmFyIiwgW2VkaXRdKTsKICAgICAgICBhZGRFcnJvcihlcnJvci5hZGRGaXgoZml4KSk7CiAgICB9Cn0=".to_string(),
            checksum: Some("f546e49732dc071fd5da82e1a2d9bcf5cf9a824c3679d8b59237c4ba23340057".to_string()),
            pattern: None,
            tree_sitter_query_base64: Some("KGZ1bmN0aW9uX2RlZmluaXRpb24KICAgIG5hbWU6IChpZGVudGlmaWVyKSBAbmFtZQogIHBhcmFtZXRlcnM6IChwYXJhbWV0ZXJzKSBAcGFyYW1zCik=".to_string()),
            arguments: vec![],
        };
        let mut request = AnalysisRequest {
            filename: "path/to/myfile.py".to_string(),
            language: Language::Python,
            file_encoding: "utf-8".to_string(),
            code_base64: "ZGVmIGZvbyhhcmcxKToKICAgIHBhc3M=".to_string(),
            configuration_base64: None,
            options: None,
            rules: vec![
                ServerRule {
                    name: "rs_one/rule_a".to_string(),
                    ..base_rule.clone()
                },
                ServerRule {
                    name: "rs_one/rule_b".to_string(),
                    ..base_rule.clone()
                },
                ServerRule {
                    name: "rs_one/rule_c".to_string(),
                    ..base_rule.clone()
                },
                ServerRule {
                    name: "rs_two/rule_a".to_string(),
                    ..base_rule.clone()
                },
            ],
        };

        // No includes/excludes
        let response = process_analysis_request(request.clone());
        assert_eq!(4, response.rule_responses.len());

        // Global exclude for 'path/to'
        request.configuration_base64 = Some(encode_base64_string(
            r#"
rulesets:
  - rs_one
ignore: [path/to]
        "#
            .to_string(),
        ));
        let response = process_analysis_request(request.clone());
        eprintln!("{:?}", response);
        assert_eq!(0, response.rule_responses.len());

        let response = process_analysis_request(AnalysisRequest {
            filename: "other/path/myfile.py".to_string(),
            ..request.clone()
        });
        assert_eq!(4, response.rule_responses.len());

        // rs_one excludes 'path/to'
        request.configuration_base64 = Some(encode_base64_string(
            r#"
rulesets:
  - rs_one:
    ignore: [path/to]
        "#
            .to_string(),
        ));
        let response = process_analysis_request(request.clone());
        eprintln!("{:?}", response);
        assert_eq!(1, response.rule_responses.len());

        let response = process_analysis_request(AnalysisRequest {
            filename: "other/path/myfile.py".to_string(),
            ..request.clone()
        });
        assert_eq!(4, response.rule_responses.len());

        // Globally only allows 'path/to'
        request.configuration_base64 = Some(encode_base64_string(
            r#"
rulesets:
  - rs_one
only: [path/to]
        "#
            .to_string(),
        ));
        let response = process_analysis_request(request.clone());
        assert_eq!(4, response.rule_responses.len());

        let response = process_analysis_request(AnalysisRequest {
            filename: "other/path/myfile.py".to_string(),
            ..request.clone()
        });
        assert_eq!(0, response.rule_responses.len());

        // rs_one only allows 'path/to'
        request.configuration_base64 = Some(encode_base64_string(
            r#"
rulesets:
  - rs_one:
    only: [path/to]
        "#
            .to_string(),
        ));
        let response = process_analysis_request(request.clone());
        assert_eq!(4, response.rule_responses.len());

        let response = process_analysis_request(AnalysisRequest {
            filename: "other/path/myfile.py".to_string(),
            ..request.clone()
        });
        assert_eq!(1, response.rule_responses.len());

        // rs_one/rule_a excludes 'path/to'
        request.configuration_base64 = Some(encode_base64_string(
            r#"
rulesets:
  - rs_one:
    rules:
      rule_a:
        ignore: [path/to]
        "#
            .to_string(),
        ));
        let response = process_analysis_request(request.clone());
        assert_eq!(3, response.rule_responses.len());

        let response = process_analysis_request(AnalysisRequest {
            filename: "other/path/myfile.py".to_string(),
            ..request.clone()
        });
        assert_eq!(4, response.rule_responses.len());

        // rs_one/rule_a only allows 'path/to'
        request.configuration_base64 = Some(encode_base64_string(
            r#"
rulesets:
  - rs_one:
    rules:
      rule_a:
        only: [path/to]
        "#
            .to_string(),
        ));
        let response = process_analysis_request(request.clone());
        assert_eq!(4, response.rule_responses.len());

        let response = process_analysis_request(AnalysisRequest {
            filename: "other/path/myfile.py".to_string(),
            ..request.clone()
        });
        assert_eq!(3, response.rule_responses.len());
    }

    #[test]
    fn test_request_configuration_invalid() {
        // invalid base64
        let mut request = AnalysisRequest {
            filename: "path/to/myfile.py".to_string(),
            language: Language::Python,
            file_encoding: "utf-8".to_string(),
            code_base64: "ZGVmIGZvbyhhcmcxKToKICAgIHBhc3M=".to_string(),
            configuration_base64: Some(":::::::".to_string()),
            options: None,
            rules: vec![ServerRule {
                name: "myrule".to_string(),
                short_description_base64: None,
                description_base64: None,
                category: Some(RuleCategory::BestPractices),
                severity: Some(RuleSeverity::Warning),
                language: Language::Python,
                rule_type: RuleType::TreeSitterQuery,
                entity_checked: None,
                code_base64: "ZnVuY3Rpb24gdmlzaXQobm9kZSwgZmlsZW5hbWUsIGNvZGUpIHsKICAgIGNvbnN0IGZ1bmN0aW9uTmFtZSA9IG5vZGUuY2FwdHVyZXNbIm5hbWUiXTsKICAgIGlmKGZ1bmN0aW9uTmFtZSkgewogICAgICAgIGNvbnN0IGVycm9yID0gYnVpbGRFcnJvcihmdW5jdGlvbk5hbWUuc3RhcnQubGluZSwgZnVuY3Rpb25OYW1lLnN0YXJ0LmNvbCwgZnVuY3Rpb25OYW1lLmVuZC5saW5lLCBmdW5jdGlvbk5hbWUuZW5kLmNvbCwKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgImludmFsaWQgbmFtZSIsICJDUklUSUNBTCIsICJzZWN1cml0eSIpOwoKICAgICAgICBjb25zdCBlZGl0ID0gYnVpbGRFZGl0KGZ1bmN0aW9uTmFtZS5zdGFydC5saW5lLCBmdW5jdGlvbk5hbWUuc3RhcnQuY29sLCBmdW5jdGlvbk5hbWUuZW5kLmxpbmUsIGZ1bmN0aW9uTmFtZS5lbmQuY29sLCAidXBkYXRlIiwgImJhciIpOwogICAgICAgIGNvbnN0IGZpeCA9IGJ1aWxkRml4KCJ1c2UgYmFyIiwgW2VkaXRdKTsKICAgICAgICBhZGRFcnJvcihlcnJvci5hZGRGaXgoZml4KSk7CiAgICB9Cn0=".to_string(),
                checksum: Some("f546e49732dc071fd5da82e1a2d9bcf5cf9a824c3679d8b59237c4ba23340057".to_string()),
                pattern: None,
                tree_sitter_query_base64: Some("KGZ1bmN0aW9uX2RlZmluaXRpb24KICAgIG5hbWU6IChpZGVudGlmaWVyKSBAbmFtZQogIHBhcmFtZXRlcnM6IChwYXJhbWV0ZXJzKSBAcGFyYW1zCik=".to_string()),
                arguments: vec![],
            }],
        };
        let response = process_analysis_request(request.clone());
        assert_eq!(
            &ERROR_CONFIGURATION_NOT_BASE64.to_string(),
            response.errors.get(0).unwrap()
        );

        // invalid configuration
        request.configuration_base64 = Some(encode_base64_string("zzzzzap!".to_string()));
        let response = process_analysis_request(request);
        assert_eq!(
            &ERROR_COULD_NOT_PARSE_CONFIGURATION.to_string(),
            response.errors.get(0).unwrap()
        );
    }

    #[test]
    fn test_request_with_arguments() {
        let request = AnalysisRequest {
            filename: "mypath/myfile.py".to_string(),
            language: Language::Python,
            file_encoding: "utf-8".to_string(),
            code_base64: "ZGVmIGZvbyhhcmcxKToKICAgIHBhc3M=".to_string(),
            configuration_base64: Some(encode_base64_string(r#"
rulesets:
  - myrs:
    rules:
      myrule:
        arguments:
          arg1:
            /: 100
            mypath: 101
            mypath/otherpath: 102
            "#.to_string())),
            options: None,
            rules: vec![
                ServerRule{
                    name: "myrs/myrule".to_string(),
                    short_description_base64: None,
                    description_base64: None,
                    category: Some(RuleCategory::BestPractices),
                    severity: Some(RuleSeverity::Warning),
                    language: Language::Python,
                    rule_type: RuleType::TreeSitterQuery,
                    entity_checked: None,
                    code_base64: encode_base64_string(r#"
function visit(node, filename, code) {
    const arg = node.context.arguments['arg1'];
    addError(buildError(1, 1, 1, 2, `argument = ${arg}`));
}
                    "#.to_string()),
                    checksum: Some("984ba37fbfdfa4245ed7922efd224365ec216e540647989ac5e8559624ba9be4".to_string()),
                    pattern: None,
                    tree_sitter_query_base64: Some("KGZ1bmN0aW9uX2RlZmluaXRpb24KICAgIG5hbWU6IChpZGVudGlmaWVyKSBAbmFtZQogIHBhcmFtZXRlcnM6IChwYXJhbWV0ZXJzKSBAcGFyYW1zCik=".to_string()),
                    arguments: vec![],
                }
            ]
        };
        let response = process_analysis_request(request);
        assert!(response.errors.is_empty());
        assert_eq!(1, response.rule_responses.len());
        assert_eq!(1, response.rule_responses[0].violations.len());
        assert!(response.rule_responses[0].violations[0]
            .message
            .contains("argument = 101"));
    }

    #[test]
    fn test_request_with_overrides() {
        let base_request = AnalysisRequest {
            filename: "mypath/myfile.py".to_string(),
            language: Language::Python,
            file_encoding: "utf-8".to_string(),
            code_base64: "ZGVmIGZvbyhhcmcxKToKICAgIHBhc3M=".to_string(),
            configuration_base64: None,
            options: None,
            rules: vec![
                ServerRule{
                    name: "myrs/myrule".to_string(),
                    short_description_base64: None,
                    description_base64: None,
                    category: Some(RuleCategory::BestPractices),
                    severity: Some(RuleSeverity::Warning),
                    language: Language::Python,
                    rule_type: RuleType::TreeSitterQuery,
                    entity_checked: None,
                    code_base64: encode_base64_string(r#"
function visit(node, filename, code) {
    const arg = node.context.arguments['arg1'];
    addError(buildError(1, 1, 1, 2, `argument = ${arg}`));
}
                    "#.to_string()),
                    checksum: Some("984ba37fbfdfa4245ed7922efd224365ec216e540647989ac5e8559624ba9be4".to_string()),
                    pattern: None,
                    tree_sitter_query_base64: Some("KGZ1bmN0aW9uX2RlZmluaXRpb24KICAgIG5hbWU6IChpZGVudGlmaWVyKSBAbmFtZQogIHBhcmFtZXRlcnM6IChwYXJhbWV0ZXJzKSBAcGFyYW1zCik=".to_string()),
                    arguments: vec![],
                }
            ]
        };

        // Default severity and category.
        let request = base_request.clone();
        let response = process_analysis_request(request);
        assert!(response.errors.is_empty(), "{:?}", response.errors);
        assert_eq!(1, response.rule_responses.len());
        assert_eq!(1, response.rule_responses[0].violations.len());
        assert_eq!(
            RuleCategory::BestPractices,
            response.rule_responses[0].violations[0].category
        );
        assert_eq!(
            RuleSeverity::Warning,
            response.rule_responses[0].violations[0].severity
        );

        // Override severity and category.
        let request = AnalysisRequest {
            configuration_base64: Some(encode_base64_string(
                r#"
rulesets:
  - myrs:
    rules:
      myrule:
        severity: ERROR
        category: CODE_STYLE
            "#
                .to_string(),
            )),
            ..base_request.clone()
        };
        let response = process_analysis_request(request);
        assert!(response.errors.is_empty());
        assert_eq!(1, response.rule_responses.len());
        assert_eq!(1, response.rule_responses[0].violations.len());
        assert_eq!(
            RuleCategory::CodeStyle,
            response.rule_responses[0].violations[0].category
        );
        assert_eq!(
            RuleSeverity::Error,
            response.rule_responses[0].violations[0].severity
        );
    }
}
