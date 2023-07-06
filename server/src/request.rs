use crate::constants::{
    ERROR_CODE_LANGUAGE_MISMATCH, ERROR_CODE_NOT_BASE64, ERROR_DECODING_BASE64,
};
use crate::model::analysis_request::{AnalysisRequest, ServerRule};
use crate::model::analysis_response::{AnalysisResponse, RuleResponse};
use kernel::analysis::analyze::analyze;
use kernel::model::analysis::AnalysisOptions;
use kernel::model::rule::{Rule, RuleCategory, RuleInternal, RuleSeverity};
use kernel::utils::decode_base64_string;
use std::collections::HashMap;

pub fn process_analysis_request(request: AnalysisRequest) -> AnalysisResponse {
    let rules_with_invalid_language: Vec<ServerRule> = request
        .rules
        .iter()
        .cloned()
        .filter(|v| v.language != request.language)
        .collect();
    if !rules_with_invalid_language.is_empty() {
        return AnalysisResponse {
            rule_responses: vec![],
            errors: vec![ERROR_CODE_LANGUAGE_MISMATCH.to_string()],
        };
    }

    // Convert the rules from the server into internal rules
    let rules_converted: Result<Vec<RuleInternal>, anyhow::Error> = request
        .rules
        .iter()
        .map(|r| Rule {
            name: r.name.clone(),
            short_description_base64: r.short_description_base64.clone(),
            description_base64: r.description_base64.clone(),
            category: r.category.unwrap_or(RuleCategory::BestPractices),
            severity: r.severity.unwrap_or(RuleSeverity::Warning),
            language: r.language,
            rule_type: r.rule_type,
            entity_checked: r.entity_checked,
            code_base64: r.code_base64.clone(),
            checksum: r.checksum.clone().unwrap_or("".to_string()),
            pattern: r.pattern.clone(),
            tree_sitter_query_base64: r.tree_sitter_query_base64.clone(),
            variables: r.variables.clone().unwrap_or(HashMap::new()),
            tests: vec![],
        })
        .map(|r| r.to_rule_internal())
        .collect::<Result<Vec<RuleInternal>, anyhow::Error>>();

    // let's try to decode the code
    let code_decoded_attempt = decode_base64_string(request.code_base64);
    if code_decoded_attempt.is_err() {
        return AnalysisResponse {
            rule_responses: vec![],
            errors: vec![ERROR_CODE_NOT_BASE64.to_string()],
        };
    }

    // execute the rule. If we fail to convert, return an error.
    match rules_converted {
        Ok(rules) => {
            let rule_results = analyze(
                &request.language,
                rules,
                &request.filename,
                code_decoded_attempt.unwrap().as_str(),
                &AnalysisOptions {
                    use_debug: false,
                    log_output: request
                        .options
                        .map(|o| o.log_output.unwrap_or(false))
                        .unwrap_or(false),
                },
            );

            let rule_responses = rule_results
                .iter()
                .map(|rr| RuleResponse {
                    identifier: rr.rule_name.clone(),
                    violations: rr.violations.clone(),
                    errors: rr.errors.clone(),
                    execution_error: rr.execution_error.clone(),
                    output: rr.output.clone(),
                    execution_time_ms: rr.execution_time_ms,
                })
                .collect();

            AnalysisResponse {
                rule_responses,
                errors: vec![],
            }
        }
        Err(_) => AnalysisResponse {
            rule_responses: vec![],
            errors: vec![ERROR_DECODING_BASE64.to_string()],
        },
    }
}

#[cfg(test)]
mod tests {
    use crate::model::analysis_request::ServerRule;
    use kernel::model::{
        common::Language,
        rule::{RuleCategory, RuleSeverity, RuleType},
    };

    use super::*;

    #[test]
    fn test_request_correct_response() {
        let request = AnalysisRequest {
            filename: "myfile.py".to_string(),
            language: Language::Python,
            file_encoding: "utf-8".to_string(),
            code_base64: "ZGVmIGZvbyhhcmcxKToKICAgIHBhc3M=".to_string(),
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
                    checksum: None,
                    pattern: None,
                    tree_sitter_query_base64: Some("KGZ1bmN0aW9uX2RlZmluaXRpb24KICAgIG5hbWU6IChpZGVudGlmaWVyKSBAbmFtZQogIHBhcmFtZXRlcnM6IChwYXJhbWV0ZXJzKSBAcGFyYW1zCik=".to_string()),
                    variables: None,
                }
            ]
        };
        let response = process_analysis_request(request);
        assert!(response.errors.is_empty());
        assert_eq!(1, response.rule_responses.len());
        assert_eq!(1, response.rule_responses.get(0).unwrap().violations.len());
    }

    #[test]
    fn test_request_invalid_base64() {
        let request = AnalysisRequest {
            filename: "myfile.py".to_string(),
            language: Language::Python,
            file_encoding: "utf-8".to_string(),
            code_base64: "ZGVmIGZvbyhhcmcxKToKI()--2#$#$Bhc3M=".to_string(),
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
                    variables: None,
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
                    checksum: Some("".to_string()),
                    pattern: None,
                    tree_sitter_query_base64: Some("KGZ1bmN0aW9uX2RlZmluaXRpb24KICAgIG5hbWU6IChpZGVudGlmaWVyKSBAbmFtZQogIHBhcmFtZXRlcnM6IChwYXJhbWV0ZXJzKSBAcGFyYW1zCik=".to_string()),
                    variables: None,
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
                    variables: None,
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
}
