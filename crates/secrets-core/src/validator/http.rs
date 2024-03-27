// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::rule::RuleId;
use crate::validator::{Candidate, SecretCategory, Validator, ValidatorError, ValidatorId};
use governor::clock::DefaultClock;
use governor::state::{InMemoryState, NotKeyed};
use governor::RateLimiter;
use retry::OperationResult;
use std::collections::HashSet;
use std::fmt::{Debug, Display, Formatter};
use std::ops::Add;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use url::Url;

#[derive(Debug, thiserror::Error)]
pub(crate) enum HttpValidatorError {
    /// The validation hit an unrecoverable error, and no further attempts will be made.
    #[error("unrecoverable validation failure")]
    RequestedAbort(Box<Result<ureq::Response, ureq::Error>>),
    #[error("validator requested retry")]
    RequestedRetry,
    #[error("invalid url: `{0}` ({1})")]
    InvalidUrl(String, url::ParseError),
    #[error("unsupported HTTP method `{0}`")]
    InvalidMethod(String),
    #[error("retrying rule validation timed out. elapsed: {0:?}")]
    RetryTimeout(Duration),
    #[error("retrying rule validation will soon time out. elapsed: {elapsed:?}")]
    RetryWillTimeout {
        elapsed: Duration,
        next_delay: Duration,
    },
    #[error("no qualifying handler that matches the server response")]
    UnhandledResponse(Box<Result<ureq::Response, ureq::Error>>),
}

/// The configuration for re-attempting failed HTTP requests.
pub(crate) struct RetryConfig {
    max_attempts: usize,
    use_jitter: bool,
    policy: RetryPolicy,
}

pub(crate) enum RetryPolicy {
    Exponential {
        base: Duration,
        factor: f64,
        maximum: Duration,
    },
    Fixed {
        duration: Duration,
    },
}

type DynFnResponseParser = dyn Fn(&Result<ureq::Response, ureq::Error>) -> NextAction;

pub struct HttpValidator {
    validator_id: ValidatorId,
    /// The maximum time allowed for a single validation attempt, inclusive of rate-limiting and retry delay.
    max_attempt_duration: Duration,
    rule_id: RuleId,
    attempted_cache: Arc<Mutex<HashSet<[u8; 32]>>>,
    rate_limiter: Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock>>,
    request_generator: RequestGenerator,
    response_parser: Box<DynFnResponseParser>,
    retry_timings_iter: Box<dyn Fn() -> Box<dyn Iterator<Item = Duration>>>,
}

/// The next action to take after an HTTP request has received a response.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum NextAction {
    /// The validation should immediately be halted, and no further retries should be attempted.
    Abort,
    /// The handler indicated that the validation should be retried.
    Retry,
    /// The handler indicated that the validation should be retried, and gave a specific time to re-attempt.
    RetryAfter(Duration),
    /// The handler successfully performed a validation and categorized the candidate.
    ReturnResult(SecretCategory),
    /// No registered handler could handle the HTTP response result, so a default fallback error was generated.
    Unhandled,
}

#[allow(clippy::type_complexity)]
struct RequestGenerator {
    agent: ureq::Agent,
    method: HttpMethod,
    format_url: Box<dyn Fn(&Candidate) -> String>,
    add_headers: Box<dyn Fn(&Candidate, &mut ureq::Request)>,
    build_post_payload: Option<Box<dyn Fn(&Candidate) -> Vec<u8>>>,
}

impl Validator for HttpValidator {
    fn id(&self) -> &ValidatorId {
        &self.validator_id
    }

    fn validate(&self, candidate: Candidate) -> Result<SecretCategory, ValidatorError> {
        let start_time = Instant::now();

        let retry_delays = (self.retry_timings_iter)();
        retry::retry(retry_delays, || {
            loop {
                let elapsed = start_time.elapsed();
                if elapsed > self.max_attempt_duration {
                    return OperationResult::Err(HttpValidatorError::RetryTimeout(elapsed));
                }
                match self.rate_limiter.check() {
                    Ok(_) => break,
                    Err(try_again_at) => {
                        let next_delay = try_again_at.wait_time_from(Instant::now());
                        let elapsed = start_time.elapsed();
                        if elapsed.add(next_delay) > self.max_attempt_duration {
                            return OperationResult::Err(HttpValidatorError::RetryWillTimeout {
                                elapsed,
                                next_delay,
                            });
                        }
                        thread::sleep(next_delay)
                    }
                }
            }

            let formatted_url = (self.request_generator.format_url)(&candidate);

            let url = match Url::parse(&formatted_url) {
                Ok(url) => url,
                Err(parse_error) => {
                    return OperationResult::Err(HttpValidatorError::InvalidUrl(
                        formatted_url,
                        parse_error,
                    ));
                }
            };

            let mut request = self
                .request_generator
                .agent
                .request(self.request_generator.method.as_ref(), url.as_str());
            (self.request_generator.add_headers)(&candidate, &mut request);

            let response = match &self.request_generator.method {
                HttpMethod::Get => request.call(),
                HttpMethod::Post => {
                    let bytes_payload = self
                        .request_generator
                        .build_post_payload
                        .as_ref()
                        .map(|get_payload_for| get_payload_for(&candidate))
                        .unwrap_or_default();
                    request.send_bytes(&bytes_payload)
                }
            };

            let next_action = (self.response_parser)(&response);

            match next_action {
                NextAction::Abort => {
                    OperationResult::Err(HttpValidatorError::RequestedAbort(Box::new(response)))
                }
                NextAction::Retry => OperationResult::Retry(HttpValidatorError::RequestedRetry),
                NextAction::RetryAfter(http_retry_after) => {
                    // NOTE: It would be nice to subtract what we know will be our next retry delay from
                    // the HTTP 429 Retry-After to maximize efficiency.
                    // However, due to `retry` API constraints, we can't peek the next retry time delay, so
                    // for now, we over-estimate the amount we need to sleep.
                    let elapsed = start_time.elapsed();
                    if elapsed.add(http_retry_after) > self.max_attempt_duration {
                        OperationResult::Err(HttpValidatorError::RetryWillTimeout {
                            elapsed,
                            next_delay: http_retry_after,
                        })
                    } else {
                        thread::sleep(http_retry_after);
                        // The `retry` API is a bit awkward here -- because of the duration calculations we've just
                        // done, the inner `HttpValidatorError::TimedOut` should never be returned because the
                        // next run of the iterator should never cause a timeout. Thus, the `time_spent` we pass in
                        // here isn't accurate, though it will not matter.
                        OperationResult::Retry(HttpValidatorError::RetryTimeout(http_retry_after))
                    }
                }
                NextAction::ReturnResult(result) => OperationResult::Ok(result),
                NextAction::Unhandled => {
                    OperationResult::Err(HttpValidatorError::UnhandledResponse(Box::new(response)))
                }
            }
        })
        .map_err(|err| ValidatorError::ChildError {
            validator_type: "http".to_string(),
            err: Box::new(err),
        })
    }
}

/// The supported HTTP methods that can be used with a request.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
enum HttpMethod {
    Get,
    Post,
}

impl AsRef<str> for HttpMethod {
    fn as_ref(&self) -> &'static str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
        }
    }
}

impl TryFrom<&str> for HttpMethod {
    type Error = HttpValidatorError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(match value {
            "GET" => Self::Get,
            "POST" => Self::Post,
            _ => Err(HttpValidatorError::InvalidMethod(value.to_string()))?,
        })
    }
}

impl Display for HttpMethod {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_ref())
    }
}
