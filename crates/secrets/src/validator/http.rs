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
