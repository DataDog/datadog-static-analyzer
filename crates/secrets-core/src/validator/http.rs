// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::rule::RuleId;
use crate::validator::http;
use crate::validator::{Candidate, SecretCategory, Validator, ValidatorError, ValidatorId};
use governor::clock::{Clock, MonotonicClock};
use governor::middleware::NoOpMiddleware;
use std::collections::HashSet;
use std::fmt::{Debug, Display, Formatter};
use std::ops::Add;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use url::Url;

/// An error returned by an [`HttpValidator`] when performing a validation attempt.
///
/// (This is a facade for [`ValidationError`] that can be cloned).
#[derive(Debug, Clone, thiserror::Error)]
pub(crate) enum HttpValidatorError {
    /// The validator either improperly formatted the request or received a response it should have
    /// been able to parse (but could not).
    #[error("local validator error: {0}")]
    LocalError(String),
    /// The validator has indicated that this validation (and all future validation attempts) will fail due
    /// to a remote server error or a transport error.
    #[error("remote validation error: {0}")]
    RemoteError(String),
    #[error("validation timed out: {attempted} attempts, {elapsed:?} elapsed")]
    TimedOut { attempted: usize, elapsed: Duration },
}

#[derive(Debug, thiserror::Error)]
enum ValidationError {
    /// The validation hit an unrecoverable error, and no further attempts will be made.
    #[error("unrecoverable validation failure")]
    RequestedAbort(Box<Result<ureq::Response, ureq::Error>>),
    #[error("invalid url: `{0}` ({1})")]
    InvalidUrl(String, url::ParseError),
    #[error("unsupported HTTP method `{0}`")]
    InvalidMethod(String),
    #[error("validation attempt exceeded the time limit")]
    RetryTimeExceeded { attempted: usize, elapsed: Duration },
    #[error("all validation retry attempts used")]
    RetryAttemptsExceeded { attempted: usize, elapsed: Duration },
    #[error("validation retry will exceed the overall time limit")]
    RetryWillExceedTime {
        attempted: usize,
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

/// The rate limiter used to cap the outbound requests per second for an [`HttpValidator`].
// NOTE: This has to be generic over `Clock` instead of the more ergonomic `governor::DefaultDirectRateLimiter`
// because we need to be able to override the clock in unit tests.
type RateLimiter<T> = governor::RateLimiter<
    governor::state::NotKeyed,
    governor::state::InMemoryState,
    T,
    NoOpMiddleware<<T as Clock>::Instant>,
>;

/// A [`Validator`] that uses outbound HTTP requests to perform validation of a secret.
///
/// This validator is tagged with a [`RuleId`] because it conceptually "belongs" to a rule.
/// Thus, this validator contains all the logic required to format an HTTP request, make the request,
/// and parse the response to determine a [`SecretCategory`].
///
/// This validator supports:
/// * A request retry policy
/// * Rate limiting of outbound requests
/// * Parsing/handling of HTTP response
pub struct HttpValidator<T: Clock = MonotonicClock> {
    /// The user-assigned [`ValidatorId`] of this validator.
    validator_id: ValidatorId,
    /// The maximum time allowed for a single validation attempt, inclusive of rate-limiting and retry delay.
    max_attempt_duration: Duration,
    /// The user-assigned [`RuleId`] of which this validator validates.
    rule_id: RuleId,
    /// A cache of the requests that have already been attempted so that no duplicates are sent.
    attempted_cache: Arc<Mutex<HashSet<[u8; 32]>>>,
    /// The [`Clock`] implementation used by the rate limiter.
    // NOTE: This needs to be included as part of the struct in order to override the clock for unit tests.
    clock: T,
    /// The limiter that enforces a maximum outbound HTTP request rate across all threads using this validator.
    rate_limiter: Arc<RateLimiter<T>>,
    /// The implementation that determines how to structure the HTTP request on a per-
    /// [`Candidate`] basis.
    request_generator: RequestGenerator,
    /// The boxed function that parses the [`ureq::Response`] to determine the appropriate action to take.
    response_parser: Box<DynFnResponseParser>,
    /// A function that generates an iterator of [`Duration`] that implements this validator's retry policy.
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

/// A function that formats data to send as part of an HTTP POST request.
/// The function must return a tuple, containing:
/// * `0`: `Vec<u8>` of the data to send
/// * `1`: `String` to send as the `Content-Type` HTTP header
type DynFnPostPayloadGenerator = dyn Fn(&Candidate) -> (Vec<u8>, String);

#[allow(clippy::type_complexity)]
pub struct RequestGenerator {
    agent: ureq::Agent,
    method: HttpMethod,
    format_url: Box<dyn Fn(&Candidate) -> String>,
    add_headers: Box<dyn Fn(&Candidate, &mut ureq::Request)>,
    build_post_payload: Option<Box<DynFnPostPayloadGenerator>>,
}

/// A wrapper around [`thread::sleep`](std::thread::sleep) that advances a [`MockClock`](crate::common::time::MockClock)
/// when running tests.
#[cfg(test)]
fn thread_sleep(duration: Duration) {
    time::MockClock::advance(duration);
}
#[cfg(not(test))]
fn thread_sleep(duration: Duration) {
    std::thread::sleep(duration);
}

impl<T: Clock> Validator for HttpValidator<T> {
    fn id(&self) -> &ValidatorId {
        &self.validator_id
    }

    fn validate(&self, candidate: Candidate) -> Result<SecretCategory, ValidatorError> {
        #[cfg(test)]
        use http::time::Instant;
        #[cfg(not(test))]
        use std::time::Instant;

        let start_time = Instant::now();

        let retry_delays = (self.retry_timings_iter)();
        let mut iter = retry_delays.peekable();
        let mut attempted = 0;

        while let Some(retry_delay) = iter.next() {
            // Certain branches can add to the required sleep time, so we track this as a mutable variable.
            let mut to_sleep = retry_delay;

            loop {
                let elapsed = start_time.elapsed();
                if elapsed > self.max_attempt_duration {
                    return Err(ValidationError::RetryTimeExceeded { attempted, elapsed }.into());
                }
                match self.rate_limiter.check() {
                    Ok(_) => break,
                    Err(try_again_at) => {
                        let next_delay = try_again_at.wait_time_from(self.clock.now());
                        let elapsed = start_time.elapsed();
                        if elapsed.add(next_delay) > self.max_attempt_duration {
                            return Err(ValidationError::RetryWillExceedTime {
                                attempted,
                                elapsed,
                                next_delay,
                            }
                            .into());
                        }
                        thread_sleep(next_delay);
                    }
                }
            }

            let formatted_url = (self.request_generator.format_url)(&candidate);

            let url = Url::parse(&formatted_url)
                .map_err(|parse_err| ValidationError::InvalidUrl(formatted_url, parse_err))?;

            let mut request = self
                .request_generator
                .agent
                .request(self.request_generator.method.as_ref(), url.as_str());
            (self.request_generator.add_headers)(&candidate, &mut request);

            attempted += 1;
            let response = match &self.request_generator.method {
                HttpMethod::Get => request.call(),
                HttpMethod::Post => {
                    let payload = self
                        .request_generator
                        .build_post_payload
                        .as_ref()
                        .map(|get_payload_for| get_payload_for(&candidate));
                    if let Some((_, content_type)) = &payload {
                        request = request.set("Content-Type", content_type);
                    }
                    request.send_bytes(&payload.map(|(bytes, _)| bytes).unwrap_or_default())
                }
            };

            let next_action = (self.response_parser)(&response);

            match next_action {
                NextAction::Abort => {
                    return Err(ValidationError::RequestedAbort(Box::new(response)).into());
                }
                NextAction::Retry => {}
                NextAction::RetryAfter(http_retry_after) => {
                    // Calculate the amount to sleep based on what we know our next sleep duration will be.
                    // For example, if the `Retry-After` is 15 seconds, and our next sleep will be 10 seconds,
                    // add an additional 5 seconds. If our next sleep is 20 seconds, add 0 seconds.
                    to_sleep += http_retry_after
                        .checked_sub(iter.peek().copied().unwrap_or_default())
                        .unwrap_or_default();
                }
                NextAction::ReturnResult(result) => return Ok(result),
                NextAction::Unhandled => {
                    return Err(ValidationError::UnhandledResponse(Box::new(response)).into());
                }
            }

            // Only sleep if this isn't the last attempt
            if iter.peek().is_some() {
                let elapsed = start_time.elapsed();
                if (elapsed + to_sleep) >= self.max_attempt_duration {
                    return Err(ValidationError::RetryWillExceedTime {
                        attempted,
                        elapsed,
                        next_delay: to_sleep,
                    }
                    .into());
                }
                thread_sleep(to_sleep);
            }
        }

        // We're within our time budget but exhausted our retry budget
        Err(ValidationError::RetryAttemptsExceeded {
            attempted,
            elapsed: start_time.elapsed(),
        }
        .into())
    }
}

impl From<ValidationError> for HttpValidatorError {
    fn from(value: ValidationError) -> Self {
        match value {
            ValidationError::RequestedAbort(res) => {
                let message = match res.as_ref() {
                    Ok(resp) => format!(
                        "validator indicated failure for response with http status: {}",
                        resp.status()
                    ),
                    Err(err) => format!("ureq error: {}", err),
                };
                Self::RemoteError(message)
            }
            ValidationError::InvalidUrl(_, _)
            | ValidationError::InvalidMethod(_)
            | ValidationError::UnhandledResponse(_) => Self::LocalError(value.to_string()),
            ValidationError::RetryTimeExceeded { attempted, elapsed }
            | ValidationError::RetryAttemptsExceeded { attempted, elapsed }
            | ValidationError::RetryWillExceedTime {
                attempted, elapsed, ..
            } => Self::TimedOut { attempted, elapsed },
        }
    }
}

impl From<HttpValidatorError> for ValidatorError {
    fn from(value: HttpValidatorError) -> Self {
        Self::ChildError {
            validator_type: "http".to_string(),
            err: Box::new(value),
        }
    }
}

impl From<ValidationError> for ValidatorError {
    fn from(value: ValidationError) -> Self {
        let http_err: HttpValidatorError = value.into();
        http_err.into()
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
    type Error = ValidationError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(match value {
            "GET" => Self::Get,
            "POST" => Self::Post,
            _ => Err(ValidationError::InvalidMethod(value.to_string()))?,
        })
    }
}

impl Display for HttpMethod {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_ref())
    }
}

#[cfg(test)]
mod time {
    use governor::clock::{Clock, Reference};
    use governor::nanos::Nanos;
    use std::cell::RefCell;
    use std::ops::Add;
    use std::time::Duration;

    thread_local! {
        static TIME: RefCell<Duration> = RefCell::new(Duration::default());
    }

    /// A clock whose time can be assigned and advanced, providing deterministic readings of "now".
    #[derive(Clone, Copy)]
    pub struct MockClock;

    impl MockClock {
        /// Sets the clock to the given [`Duration`].
        pub fn set(time: Duration) {
            TIME.with_borrow_mut(|current| *current = time);
        }

        /// Advances the clock forward by the given [`Duration`].
        pub fn advance(time: Duration) {
            TIME.with_borrow_mut(|current| *current += time);
        }

        /// Returns the current time.
        pub fn current_time() -> Duration {
            TIME.with_borrow(|t| *t)
        }
    }

    /// A partial drop-in replacement for [`std::time::Instant`] that bases its time reading off of a [`MockClock`].
    #[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
    pub struct Instant(Duration);

    impl Instant {
        pub fn now() -> Self {
            Self(MockClock::current_time())
        }

        pub fn elapsed(&self) -> Duration {
            MockClock::current_time() - self.0
        }
    }

    impl Clock for MockClock {
        type Instant = Instant;

        fn now(&self) -> Self::Instant {
            Instant::now()
        }
    }

    impl Reference for Instant {
        fn duration_since(&self, earlier: Self) -> Nanos {
            Nanos::new(self.0.saturating_sub(earlier.0).as_nanos() as u64)
        }

        fn saturating_sub(&self, duration: Nanos) -> Self {
            Instant(self.0.saturating_sub(duration.into()))
        }
    }

    impl Add<Nanos> for Instant {
        type Output = Instant;

        fn add(self, rhs: Nanos) -> Self::Output {
            let rhs: Duration = rhs.into();
            Instant(self.0 + rhs)
        }
    }
}
