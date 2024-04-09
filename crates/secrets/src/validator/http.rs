// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use secrets_core::ureq;
use secrets_core::validator::http::{
    DynFnPostPayloadGenerator, GeneratorResult, HttpResponse, HttpValidator, HttpValidatorBuilder,
    NextAction, RequestGeneratorBuilder, ResponseParserBuilder, RetryConfig,
};
use secrets_core::validator::{Candidate, ValidatorId};
use std::borrow::Cow;

use crate::check::Check;
use crate::rule_file::make_candidate_provider;
use crate::rule_file::validator::http::{
    RawCfgSimpleRequest, RawMethod, RawRequest, RawResponseHandler,
};
use secrets_core::Checker;

const USER_AGENT: &str = "Datadog/StaticAnalyzer";

/// Builds an [`HttpValidator`] from the user input.
///
/// This is not a fallible action, even if the user input is syntactically correct but invalid for any reason.
/// Invalid user input will cause a runtime error during validation.
pub fn build_simple_http(
    raw: RawCfgSimpleRequest,
    validator_id: ValidatorId,
    retry_config: &RetryConfig,
) -> HttpValidator {
    let RawRequest {
        url: template_url,
        headers: template_headers,
        method,
        body,
    } = raw.request;
    let url_generator = Box::new(move |candidate: &Candidate| -> GeneratorResult<String> {
        let provider = make_candidate_provider(candidate);
        Ok(template_url.try_evaluate(&provider).map_err(Box::new)?)
    });
    let build_post_payload = (method == RawMethod::Post && body.is_some()).then(|| {
        let body = body.expect("body should have already been verified as Some");
        let boxed: Box<DynFnPostPayloadGenerator> = Box::new(
            move |candidate: &Candidate| -> GeneratorResult<(Vec<u8>, String)> {
                let provider = make_candidate_provider(candidate);
                let text = body.data.try_evaluate(&provider).map_err(Box::new)?;
                Ok((text.into_bytes(), body.content_type.clone()))
            },
        );
        boxed
    });
    let agent = ureq::Agent::new();
    let mut request_generator = match method {
        RawMethod::Get => RequestGeneratorBuilder::http_get(agent, url_generator),
        RawMethod::Post => {
            RequestGeneratorBuilder::http_post(agent, url_generator, build_post_payload)
        }
    };
    if let Some(headers) = template_headers {
        for (header, value) in headers.0 {
            if value.is_dynamic() {
                let dyn_fn = move |cand: &Candidate| -> GeneratorResult<String> {
                    let provider = make_candidate_provider(cand);
                    Ok(value.try_evaluate(&provider).map_err(Box::new)?)
                };
                request_generator = request_generator.dynamic_header(header, Box::new(dyn_fn))
            } else {
                request_generator = request_generator.header(header, value.raw());
            }
        }
    }
    request_generator = request_generator.header("User-Agent", USER_AGENT);
    let request_generator = request_generator.build();

    let RawResponseHandler {
        handler_list,
        default_result,
    } = raw.response_handler;

    let mut response_handler = ResponseParserBuilder::new();
    for raw_handler in handler_list {
        let (raw_check, raw_action) = (raw_handler.on_match, raw_handler.action);
        let raw_action = raw_action.into_inner();
        let checker = Check::from_raw(&raw_check);
        let handler = move |req_result: &Result<HttpResponse, ureq::Error>| -> NextAction {
            let input = match raw_check.input_variable() {
                "http.response.body" => req_result
                    .as_ref()
                    .map(|resp| Some(Cow::Borrowed(resp.body())))
                    .unwrap_or(None),
                "http.response.code" => {
                    let response_code = match req_result.as_ref() {
                        Ok(response) => Some(response.status()),
                        Err(ureq::Error::Status(status, _)) => Some(*status),
                        _ => None,
                    };
                    response_code.map(|code| Cow::Owned(code.to_string()))
                }
                _ => raw_check
                    .input_variable()
                    .strip_prefix("http.response.header.")
                    .and_then(|header| {
                        req_result.as_ref().map_or(None, |response| {
                            response.first_header(header).map(Cow::Borrowed)
                        })
                    }),
            };
            let Some(input) = input else {
                return NextAction::Unhandled;
            };

            if checker.check(input.as_bytes()) {
                raw_action.clone().into()
            } else {
                NextAction::Unhandled
            }
        };
        response_handler = response_handler.add_handler(Box::new(handler));
    }
    response_handler =
        response_handler.set_default(NextAction::ReturnResult(default_result.into()));
    let response_handler = response_handler.build();

    HttpValidatorBuilder::new(validator_id, request_generator, response_handler)
        .retry_config(retry_config.clone())
        .build()
}

#[cfg(test)]
mod tests {
    use crate::rule_file::validator::http::RawCfgSimpleRequest;
    use crate::validator::http::{build_simple_http, USER_AGENT};
    use httpmock::MockServer;
    use secrets_core::rule::{LocatedString, RuleMatch};
    use secrets_core::validator::http::{
        HttpValidator, HttpValidatorError, RetryConfig, RetryPolicy,
    };
    use secrets_core::validator::{
        Candidate, SecretCategory, Severity, ValidatorError, ValidatorId,
    };
    use secrets_core::Validator;
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::time::Duration;

    const VALID: &str = "121bdc4e---------valid----------49935a92";

    /// A default `response-handler` to inject for tests that aren't concerned with the response.
    const DEFAULT_RESPONSE: &str = "\
response-handler:
  handler-list:
  default-result:
    secret: INCONCLUSIVE
    severity: NOTICE
";

    /// Builds a candidate with incorrect location data (done here for simplicity, as these tests don't need location)
    fn to_candidate(text: &str, captures: HashMap<&'static str, &'static str>) -> Candidate {
        let captures = captures
            .into_iter()
            .map(|(k, v)| {
                let v = LocatedString {
                    inner: v.to_string(),
                    byte_span: Default::default(),
                    point_span: Default::default(),
                };
                (k.to_string(), v)
            })
            .collect::<HashMap<_, _>>();
        Candidate {
            source: PathBuf::from("foo/bar/baz.rs"),
            rule_match: RuleMatch {
                rule_id: "test-rule".into(),
                matched: LocatedString {
                    inner: text.to_string(),
                    byte_span: Default::default(),
                    point_span: Default::default(),
                },
                captures,
            },
        }
    }

    fn make_validator(request_yaml: &str, response_yaml: &str) -> HttpValidator {
        let cfg: RawCfgSimpleRequest =
            serde_yaml::from_str(&format!("{}\n{}", request_yaml, response_yaml)).unwrap();
        let validator_id: ValidatorId = "http-validator_test-rule".into();
        let retry_config = RetryConfig {
            max_attempts: 3,
            use_jitter: false,
            policy: RetryPolicy::Fixed {
                duration: Duration::from_millis(1),
            },
        };
        build_simple_http(cfg, validator_id, &retry_config)
    }

    /// Generates a test case that creates a validator from the provided [`RawRequest`](crate::rule_file::validator::http::RawRequest)
    /// and asserts that it is parsed into an [`HttpValidator`] that formats an HTTP request as specified.
    ///
    /// Note: `<__cfg(test)_magic_url__>` is treated as a "magic" const that will transparently be replaced with the [`MockServer`] URL.
    macro_rules! test_request {
        (
            $request_yaml:literal,
            $when:ident
            $(. $call:ident($($args:tt)*))+
        ) => {{
                let ms = MockServer::start();
                let mock = ms.mock(|$when, then| {
                    $when
                    $(.$call($($args)*))+;
                    then.status(200);
                });
                let yaml = $request_yaml.replace("<__cfg(test)_magic_url__>", &ms.base_url());
                let validator = make_validator(&yaml, DEFAULT_RESPONSE);
                let captures = HashMap::from([("inner_token", "49935a92")]);
                let _ = validator.validate(to_candidate(VALID, captures)).unwrap();
                mock.assert_hits(1);
            }}
    }

    #[test]
    fn parse_request_get_with_headers() {
        test_request!(
            "\
request:
  url: <__cfg(test)_magic_url__>
  method: GET
  headers:
    Accept: test/test
",
            assert.header("Accept", "test/test").method("GET")
        );
    }

    #[test]
    fn parse_request_get_no_headers() {
        test_request!(
            "\
request:
  url: <__cfg(test)_magic_url__>
  method: GET
",
            assert.method("GET")
        );
    }

    #[test]
    fn parse_request_captures() {
        test_request!(
            r#"
request:
  url: <__cfg(test)_magic_url__>/?token=abc_${{ candidate.captures.inner_token }}
  method: GET
  headers:
    Authentication: Bearer ${{ candidate }}
"#,
            assert
                .method("GET")
                .query_param("token", "abc_49935a92")
                .header("Authentication", format!("Bearer {}", VALID))
        );
    }

    #[test]
    fn parse_request_post_body() {
        test_request!(
            "\
request:
  url: <__cfg(test)_magic_url__>
  method: POST
  headers:
    Accept: test/test
  body:
    data: abc
    content-type: text/plain
",
            assert
                .header("Accept", "test/test")
                .method("POST")
                .body("abc")
                .header("Content-Type", "text/plain")
        );
    }

    #[test]
    fn parse_request_post_no_body() {
        test_request!(
            "\
request:
  url: <__cfg(test)_magic_url__>
  method: POST
  headers:
    Accept: test/test
",
            assert.header("Accept", "test/test").method("POST")
        );
    }

    /// The User-Agent header cannot be overridden
    #[test]
    fn parse_request_restricted_headers() {
        test_request!(
            "\
request:
  url: <__cfg(test)_magic_url__>
  method: GET
  headers:
    User-Agent: FooBot
",
            assert.method("GET").header("User-Agent", USER_AGENT)
        );
    }
}
