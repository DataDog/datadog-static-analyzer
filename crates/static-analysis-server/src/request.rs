use crate::constants::{
    ERROR_CODE_LANGUAGE_MISMATCH, ERROR_CODE_NOT_BASE64, ERROR_CONFIGURATION_NOT_BASE64,
    ERROR_COULD_NOT_PARSE_CONFIGURATION,
};
use crate::model::analysis_request::AnalysisRequest;
use crate::model::analysis_response::RuleResponse;
use crate::model::violation::ServerViolation;
use common::analysis_options::AnalysisOptions;
use kernel::analysis::analyze::analyze_with;
use kernel::analysis::ddsa_lib::JsRuntime;
use kernel::config::file_v1::parse_config_file;
use kernel::model::rule::RuleInternal;
use kernel::rule_config::RuleConfigProvider;
use kernel::utils::decode_base64_string;
use std::borrow::Borrow;
use std::sync::Arc;
use std::time::Duration;

#[tracing::instrument(skip_all)]
pub fn process_analysis_request<T: Borrow<RuleInternal>>(
    request: AnalysisRequest<T>,
    runtime: &mut JsRuntime,
    timeout: Option<Duration>,
) -> Result<Vec<RuleResponse>, &'static str> {
    tracing::debug!("Processing analysis request");

    // Decode the configuration, if present.
    let configuration = if let Some(config_b64) = request.configuration_base64 {
        let config =
            decode_base64_string(config_b64).map_err(|_| ERROR_CONFIGURATION_NOT_BASE64)?;
        let cfg_file =
            parse_config_file(&config).map_err(|_| ERROR_COULD_NOT_PARSE_CONFIGURATION)?;
        Some(cfg_file)
    } else {
        None
    };

    // If the file is excluded by the global configuration, stop early.
    if configuration
        .as_ref()
        .is_some_and(|cfg_file| !cfg_file.paths.allows_file(&request.filename))
    {
        tracing::debug!("Skipped excluded file: {}", request.filename);
        return Ok(vec![]);
    }

    // Extract the rule configuration from the configuration file.
    let rule_config_provider = configuration
        .as_ref()
        .map(RuleConfigProvider::from_config)
        .unwrap_or_default();
    let rule_config = rule_config_provider.config_for_file(&request.filename);

    if let Some(rule) = request
        .rules
        .iter()
        .find(|&rule| rule.borrow().language != request.language)
    {
        let rule = rule.borrow();
        tracing::info!(
            "Validation error: request language is `{}`, but rule `{}` language is `{}`",
            request.language,
            rule.name,
            rule.language
        );
        return Err(ERROR_CODE_LANGUAGE_MISMATCH);
    }

    if request.rules.is_empty() {
        tracing::info!("Successfully completed analysis for 0 rules");
        return Ok(vec![]);
    }

    // let's try to decode the code
    let code = decode_base64_string(request.code_base64).map_err(|_| ERROR_CODE_NOT_BASE64)?;
    let code: Arc<str> = Arc::from(code);

    let rules_count = request.rules.len();
    let rules_str = if rules_count == 1 { "rule" } else { "rules" };
    let rules_list = request
        .rules
        .iter()
        .map(|r| r.borrow().name.as_str())
        .collect::<Vec<&str>>()
        .join(", ");

    // execute the rule. If we fail to convert, return an error.
    let rule_results = analyze_with(
        runtime,
        &request.language,
        request.rules,
        &Arc::from(request.filename),
        &code,
        &rule_config,
        &AnalysisOptions {
            use_debug: false,
            log_output: request
                .options
                .map(|o| o.log_output.unwrap_or(false))
                .unwrap_or(false),
            ignore_generated_files: false,
            timeout,
        },
    );

    let rule_responses = rule_results
        .iter()
        .map(|rr| RuleResponse {
            identifier: rr.rule_name.clone(),
            violations: rr.violations.iter().map(ServerViolation::from).collect(),
            errors: rr.errors.clone(),
            execution_error: rr.execution_error.clone(),
            output: rr.output.clone(),
            execution_time_ms: rr.execution_time_ms,
        })
        .collect::<Vec<_>>();

    tracing::info!(
        "Successfully completed analysis for {} {} ({})",
        rules_count,
        rules_str,
        rules_list
    );

    Ok(rule_responses)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{AnalysisRequest, RuleResponse};
    use crate::constants::{
        ERROR_CHECKSUM_MISMATCH, ERROR_CODE_LANGUAGE_MISMATCH, ERROR_CODE_NOT_BASE64,
        ERROR_CONFIGURATION_NOT_BASE64, ERROR_COULD_NOT_PARSE_CONFIGURATION, ERROR_DECODING_BASE64,
        ERROR_PARSING_RULE,
    };
    use crate::model::analysis_request::{AnalysisRequestOptions, ServerRule};
    use kernel::analysis::ddsa_lib;
    use kernel::model::rule::{compute_sha256, RuleInternal};
    use kernel::model::{
        analysis::ERROR_RULE_TIMEOUT,
        common::Language,
        rule::{RuleCategory, RuleSeverity, RuleType},
    };
    use kernel::utils::encode_base64_string;

    /// A shorthand helper function to call [`process_analysis_request`](super::process_analysis_request)
    /// without requiring a `ServerRule` -> `RuleInternal` conversion or an explicitly-created [`JsRuntime`].
    pub fn shorthand_process_req(
        request: AnalysisRequest<ServerRule>,
    ) -> Result<Vec<RuleResponse>, &'static str> {
        shorthand_process_req_with_timeout(request, None)
    }

    pub fn shorthand_process_req_with_timeout(
        request: AnalysisRequest<ServerRule>,
        timeout: Option<Duration>,
    ) -> Result<Vec<RuleResponse>, &'static str> {
        let v8 = ddsa_lib::test_utils::cfg_test_v8();
        let mut runtime = v8.new_runtime();

        let rules = request
            .rules
            .into_iter()
            .map(RuleInternal::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        let req_with_internal = AnalysisRequest::<RuleInternal> {
            filename: request.filename,
            language: request.language,
            file_encoding: request.file_encoding,
            code_base64: request.code_base64,
            rules,
            configuration_base64: request.configuration_base64,
            options: request.options,
        };
        super::process_analysis_request(req_with_internal, &mut runtime, timeout)
    }

    /// A sample JavaScript rule and tree-sitter query used to assert violation behavior.
    const DEFAULT_RULE: (&str, &str) = (
        // language=javascript
        r#"
function visit(node, filename, code) {
    const functionName = node.captures["name"];
    if(functionName) {
        const error = buildError(functionName.start.line, functionName.start.col, functionName.end.line, functionName.end.col,
                                 "invalid name", "CRITICAL", "security");

        const edit = buildEdit(functionName.start.line, functionName.start.col, functionName.end.line, functionName.end.col, "update", "bar");
        const fix = buildFix("use bar", [edit]);
        addError(error.addFix(fix));
    }
}"#,
        "\
(function_definition
    name: (identifier) @name
    parameters: (parameters) @params
)",
    );

    /// A shorthand to build a [`ServerRule`] for tests.
    fn make_server_rule(rule_name: &str, language: Language, rule: (&str, &str)) -> ServerRule {
        let code_base64 = encode_base64_string(rule.0.to_string());
        let ts_query_b64 = encode_base64_string(rule.1.to_string());
        let mut server_rule = ServerRule {
            name: rule_name.to_string(),
            short_description_base64: None,
            description_base64: None,
            category: Some(RuleCategory::BestPractices),
            severity: Some(RuleSeverity::Warning),
            language,
            rule_type: RuleType::TreeSitterQuery,
            entity_checked: None,
            code_base64,
            checksum: None,
            pattern: None,
            tree_sitter_query_base64: Some(ts_query_b64),
            arguments: vec![],
        };
        update_checksum(&mut server_rule, true);
        server_rule
    }

    /// A shorthand to assign either a correct or incorrect checksum to a rule.
    fn update_checksum(server_rule: &mut ServerRule, correct: bool) {
        server_rule.checksum = if correct {
            Some(compute_sha256(&server_rule.code_base64))
        } else {
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string())
        }
    }

    #[test]
    fn test_request_single_region_correct_response() {
        let request = AnalysisRequest {
            filename: "myfile.py".to_string(),
            language: Language::Python,
            file_encoding: "utf-8".to_string(),
            code_base64: "ZGVmIGZvbyhhcmcxKToKICAgIHBhc3M=".to_string(),
            configuration_base64: None,
            options: None,
            rules: vec![make_server_rule("myrule", Language::Python, DEFAULT_RULE)],
        };
        let rule_responses = shorthand_process_req(request).unwrap();
        assert_eq!(1, rule_responses.len());
        let violations = &rule_responses[0].violations;
        assert_eq!(1, violations.len());
        assert!(violations[0].0.taint_flow.is_none());
    }

    #[test]
    fn test_request_taint_flow_correct_response() {
        // language=java
        let text = "\
class Test {
    void test(String input) {
        String a = input;
        var b = a;
        execute(b);
    }
}
";
        let ts_query = "\
(argument_list (identifier) @arg)
";
        // language=javascript
        let rule_code = r#"
function visit(captures) {
    const arg = captures.get("arg");
    const sourceFlows = ddsa.getTaintSources(arg);
    const v = Violation.new("flow violation", sourceFlows[0]);
    addError(v);
}
"#;

        let request = AnalysisRequest {
            filename: "flow.java".to_string(),
            language: Language::Java,
            file_encoding: "utf-8".to_string(),
            code_base64: encode_base64_string(text.to_string()),
            configuration_base64: None,
            options: None,
            rules: vec![make_server_rule(
                "java-security/flow-rule",
                Language::Java,
                (rule_code, ts_query),
            )],
        };
        let rule_responses = shorthand_process_req(request).unwrap();
        let taint_flow_regions = rule_responses[0].violations[0].0.taint_flow.as_ref();
        assert_eq!(taint_flow_regions.unwrap().len(), 6);
    }

    #[test]
    fn test_invalid_checksum() {
        let mut server_rule = make_server_rule("myrule", Language::Python, DEFAULT_RULE);
        update_checksum(&mut server_rule, false);

        let request = AnalysisRequest {
            filename: "myfile.py".to_string(),
            language: Language::Python,
            file_encoding: "utf-8".to_string(),
            code_base64: "ZGVmIGZvbyhhcmcxKToKICAgIHBhc3M=".to_string(),
            configuration_base64: None,
            options: None,
            rules: vec![server_rule],
        };
        let err_message = shorthand_process_req(request).unwrap_err();
        assert_eq!(err_message, ERROR_CHECKSUM_MISMATCH);
    }

    #[test]
    fn test_request_invalid_file_contents_base64() {
        let request = AnalysisRequest {
            filename: "myfile.py".to_string(),
            language: Language::Python,
            file_encoding: "utf-8".to_string(),
            code_base64: "ZGVmIGZvbyhhcmcxKToKI()--2#$#$Bhc3M=".to_string(),
            configuration_base64: None,
            options: None,
            rules: vec![make_server_rule("myrule", Language::Python, DEFAULT_RULE)],
        };
        let err_message = shorthand_process_req(request).unwrap_err();
        assert_eq!(err_message, ERROR_CODE_NOT_BASE64);
    }

    #[test]
    fn test_request_invalid_rule_code_base64_encoding() {
        let mut server_rule = make_server_rule("myrule", Language::Python, DEFAULT_RULE);
        server_rule.code_base64 = format!("!!! {}", server_rule.code_base64);
        update_checksum(&mut server_rule, true);

        let request = AnalysisRequest {
            filename: "myfile.py".to_string(),
            language: Language::Python,
            file_encoding: "utf-8".to_string(),
            code_base64: "ZGVmIGZvbyhhcmcxKToKICAgIHBhc3M=".to_string(),
            configuration_base64: None,
            options: None,
            rules: vec![server_rule],
        };
        let err_message = shorthand_process_req(request).unwrap_err();
        assert_eq!(err_message, ERROR_DECODING_BASE64);
    }

    #[test]
    fn test_request_invalid_rule_tree_sitter_query() {
        let server_rule = make_server_rule(
            "myrule",
            Language::Python,
            (DEFAULT_RULE.0, &format!("!!! {}", DEFAULT_RULE.1)),
        );

        let request = AnalysisRequest {
            filename: "myfile.rb".to_string(),
            language: Language::Python,
            file_encoding: "utf-8".to_string(),
            code_base64: "ZGVmIGZvbyhhcmcxKToKICAgIHBhc3M=".to_string(),
            configuration_base64: None,
            options: None,
            rules: vec![server_rule],
        };
        let err_message = shorthand_process_req(request).unwrap_err();
        assert_eq!(err_message, ERROR_PARSING_RULE);
    }

    #[test]
    fn test_request_invalid_language() {
        let request = AnalysisRequest {
            filename: "myfile.py".to_string(),
            language: Language::JavaScript,
            file_encoding: "utf-8".to_string(),
            code_base64: "ZGVmIGZvbyhhcmcxKToKICAgIHBhc3M=".to_string(),
            configuration_base64: None,
            options: None,
            rules: vec![make_server_rule("myrule", Language::Python, DEFAULT_RULE)],
        };
        let err_message = shorthand_process_req(request).unwrap_err();
        assert_eq!(err_message, ERROR_CODE_LANGUAGE_MISMATCH);
    }

    #[test]
    fn test_request_configuration_includes_excludes() {
        let base_rule = make_server_rule("myrule", Language::Python, DEFAULT_RULE);
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
        let rule_responses = shorthand_process_req(request.clone()).unwrap();
        assert_eq!(4, rule_responses.len());

        // Global exclude for 'path/to'
        request.configuration_base64 = Some(encode_base64_string(
            r#"
rulesets:
  - rs_one
ignore: [path/to]
        "#
            .to_string(),
        ));
        let rule_responses = shorthand_process_req(request.clone()).unwrap();
        assert_eq!(0, rule_responses.len());

        let rule_responses = shorthand_process_req(AnalysisRequest {
            filename: "other/path/myfile.py".to_string(),
            ..request.clone()
        })
        .unwrap();
        assert_eq!(4, rule_responses.len());

        // rs_one excludes 'path/to'
        request.configuration_base64 = Some(encode_base64_string(
            r#"
rulesets:
  - rs_one:
    ignore: [path/to]
        "#
            .to_string(),
        ));
        let rule_responses = shorthand_process_req(request.clone()).unwrap();
        assert_eq!(1, rule_responses.len());

        let rule_responses = shorthand_process_req(AnalysisRequest {
            filename: "other/path/myfile.py".to_string(),
            ..request.clone()
        })
        .unwrap();
        assert_eq!(4, rule_responses.len());

        // Globally only allows 'path/to'
        request.configuration_base64 = Some(encode_base64_string(
            r#"
rulesets:
  - rs_one
only: [path/to]
        "#
            .to_string(),
        ));
        let rule_responses = shorthand_process_req(request.clone()).unwrap();
        assert_eq!(4, rule_responses.len());

        let rule_responses = shorthand_process_req(AnalysisRequest {
            filename: "other/path/myfile.py".to_string(),
            ..request.clone()
        })
        .unwrap();
        assert_eq!(0, rule_responses.len());

        // rs_one only allows 'path/to'
        request.configuration_base64 = Some(encode_base64_string(
            r#"
rulesets:
  - rs_one:
    only: [path/to]
        "#
            .to_string(),
        ));
        let rule_responses = shorthand_process_req(request.clone()).unwrap();
        assert_eq!(4, rule_responses.len());

        let rule_responses = shorthand_process_req(AnalysisRequest {
            filename: "other/path/myfile.py".to_string(),
            ..request.clone()
        })
        .unwrap();
        assert_eq!(1, rule_responses.len());

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
        let rule_responses = shorthand_process_req(request.clone()).unwrap();
        assert_eq!(3, rule_responses.len());

        let rule_responses = shorthand_process_req(AnalysisRequest {
            filename: "other/path/myfile.py".to_string(),
            ..request.clone()
        })
        .unwrap();
        assert_eq!(4, rule_responses.len());

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
        let rule_responses = shorthand_process_req(request.clone()).unwrap();
        assert_eq!(4, rule_responses.len());

        let rule_responses = shorthand_process_req(AnalysisRequest {
            filename: "other/path/myfile.py".to_string(),
            ..request.clone()
        })
        .unwrap();
        assert_eq!(3, rule_responses.len());
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
            rules: vec![make_server_rule("myrule", Language::Python, DEFAULT_RULE)],
        };
        let err_message = shorthand_process_req(request.clone()).unwrap_err();
        assert_eq!(err_message, ERROR_CONFIGURATION_NOT_BASE64);

        // invalid configuration
        request.configuration_base64 = Some(encode_base64_string("zzzzzap!".to_string()));
        let err_message = shorthand_process_req(request).unwrap_err();
        assert_eq!(err_message, ERROR_COULD_NOT_PARSE_CONFIGURATION);
    }

    #[test]
    fn test_request_with_arguments() {
        let request = AnalysisRequest {
            filename: "mypath/myfile.py".to_string(),
            language: Language::Python,
            file_encoding: "utf-8".to_string(),
            code_base64: "ZGVmIGZvbyhhcmcxKToKICAgIHBhc3M=".to_string(),
            configuration_base64: Some(encode_base64_string(
                r#"
rulesets:
  - myrs:
    rules:
      myrule:
        arguments:
          arg1:
            /: 100
            mypath: 101
            mypath/otherpath: 102
            "#
                .to_string(),
            )),
            options: None,
            rules: vec![make_server_rule(
                "myrs/myrule",
                Language::Python,
                (
                    r#"
function visit(node, filename, code) {
    const arg = node.context.arguments['arg1'];
    addError(buildError(1, 1, 1, 2, `argument = ${arg}`));
}
                    "#,
                    DEFAULT_RULE.1,
                ),
            )],
        };
        let rule_responses = shorthand_process_req(request).unwrap();
        assert_eq!(1, rule_responses.len());
        assert_eq!(1, rule_responses[0].violations.len());
        let message = &rule_responses[0].violations[0].0.message;
        assert!(message.contains("argument = 101"));
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
            rules: vec![make_server_rule(
                "myrs/myrule",
                Language::Python,
                (
                    r#"
function visit(node, filename, code) {
    const arg = node.context.arguments['arg1'];
    addError(buildError(1, 1, 1, 2, `argument = ${arg}`));
}
                    "#,
                    DEFAULT_RULE.1,
                ),
            )],
        };

        // Default severity and category.
        let request = base_request.clone();
        let rule_responses = shorthand_process_req(request).unwrap();
        assert_eq!(1, rule_responses.len());
        assert_eq!(1, rule_responses[0].violations.len());
        assert_eq!(
            RuleCategory::BestPractices,
            rule_responses[0].violations[0].0.category
        );
        assert_eq!(
            RuleSeverity::Warning,
            rule_responses[0].violations[0].0.severity
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
        let rule_responses = shorthand_process_req(request).unwrap();
        assert_eq!(1, rule_responses.len());
        assert_eq!(1, rule_responses[0].violations.len());
        assert_eq!(
            RuleCategory::CodeStyle,
            rule_responses[0].violations[0].0.category
        );
        assert_eq!(
            RuleSeverity::Error,
            rule_responses[0].violations[0].0.severity
        );

        // Per-path severity override.
        let request = AnalysisRequest {
            configuration_base64: Some(encode_base64_string(
                r#"
rulesets:
  - myrs:
    rules:
      myrule:
        severity:
          /: ERROR
          somepath: WARNING
          mypath: NOTICE
          mypath/my: ERROR
        category: CODE_STYLE
            "#
                .to_string(),
            )),
            ..base_request.clone()
        };
        let rule_responses = shorthand_process_req(request).unwrap();
        assert_eq!(1, rule_responses.len());
        assert_eq!(1, rule_responses[0].violations.len());
        assert_eq!(
            RuleCategory::CodeStyle,
            rule_responses[0].violations[0].0.category
        );
        assert_eq!(
            RuleSeverity::Notice,
            rule_responses[0].violations[0].0.severity
        );
    }

    /// Tests that a rule with an expensive tree-sitter query won't get stuck processing for a long
    /// time, and will return a rule response that contains a timeout error.
    #[test]
    fn test_query_execution_timeout() {
        let base_rule =
            ServerRule{
                    name: "ruleset/rule-name".to_string(),
                    short_description_base64: None,
                    description_base64: None,
                    category: Some(RuleCategory::BestPractices),
                    severity: Some(RuleSeverity::Warning),
                    language: Language::JavaScript,
                    rule_type: RuleType::TreeSitterQuery,
                    entity_checked: None,
                    code_base64: "ZnVuY3Rpb24gdmlzaXQobm9kZSwgZmlsZW5hbWUsIGNvZGUpIHsKICAgIGNvbnN0IGNhcHR1cmVkID0gbm9kZS5jYXB0dXJlc1siaWRfbm9kZSJdOwoJY29uc29sZS5sb2coZ2V0Q29kZUZvck5vZGUoY2FwdHVyZWQsIGNvZGUpKTsKfQ==".to_string(),
                    checksum: Some("f7e512c599b80f91b3e483f40c63192156cc3ad8cf53efae87315d0db22755c4".to_string()),
                    pattern: None,
                    tree_sitter_query_base64: Some("KAogIChmdW5jdGlvbl9kZWNsYXJhdGlvbgogICAgYm9keTogKHN0YXRlbWVudF9ibG9jawogICAgICAobGV4aWNhbF9kZWNsYXJhdGlvbgogICAgICAgICh2YXJpYWJsZV9kZWNsYXJhdG9yCiAgICAgICAgICBuYW1lOiAoaWRlbnRpZmllcikKICAgICAgICAgIHZhbHVlOiAobnVtYmVyKQogICAgICAgICkKICAgICAgKQogICAgKQogICkgQGZvbwogIChmdW5jdGlvbl9kZWNsYXJhdGlvbgogICAgYm9keTogKHN0YXRlbWVudF9ibG9jawogICAgICAobGV4aWNhbF9kZWNsYXJhdGlvbgogICAgICAgICh2YXJpYWJsZV9kZWNsYXJhdG9yCiAgICAgICAgICBuYW1lOiAoaWRlbnRpZmllcikKICAgICAgICAgIHZhbHVlOiAobnVtYmVyKQogICAgICAgICkKICAgICAgKQogICAgKQogICkgQGZvbwogIChmdW5jdGlvbl9kZWNsYXJhdGlvbgogICAgYm9keTogKHN0YXRlbWVudF9ibG9jawogICAgICAobGV4aWNhbF9kZWNsYXJhdGlvbgogICAgICAgICh2YXJpYWJsZV9kZWNsYXJhdG9yCiAgICAgICAgICBuYW1lOiAoaWRlbnRpZmllcikKICAgICAgICAgIHZhbHVlOiAobnVtYmVyKQogICAgICAgICkKICAgICAgKQogICAgKQogICkgQGZvbwop".to_string()),
                    arguments: vec![],
                };

        let request = AnalysisRequest {
            filename: "myfile.js".to_string(),
            language: Language::JavaScript,
            file_encoding: "utf-8".to_string(),
            code_base64: encode_base64_string("function foo() { const baz = 1; }".repeat(10000)),
            configuration_base64: None,
            options: Some(AnalysisRequestOptions {
                use_tree_sitter: None,
                log_output: Some(true),
            }),
            rules: vec![base_rule.clone()],
        };
        let rule_responses = shorthand_process_req(request.clone()).unwrap();
        assert_eq!(rule_responses.len(), 1);
        assert_eq!(rule_responses[0].errors.len(), 1);
        assert_eq!(rule_responses[0].errors[0], ERROR_RULE_TIMEOUT.to_string());
    }
}
