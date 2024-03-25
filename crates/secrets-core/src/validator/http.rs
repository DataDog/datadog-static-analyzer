// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::rule::RuleId;
use crate::validator::http;
use crate::validator::{Candidate, SecretCategory, Validator, ValidatorError, ValidatorId};
use governor::clock::{Clock, DefaultClock};
use governor::middleware::NoOpMiddleware;
use std::collections::HashSet;
use std::fmt::{Debug, Display, Formatter};
use std::num::NonZeroU32;
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

const DEFAULT_MAX_ATTEMPTS: usize = 4;
const DEFAULT_USE_JITTER: bool = true;
const DEFAULT_BASE: Duration = Duration::from_secs(1);
const DEFAULT_FACTOR: f32 = 1.6;
const DEFAULT_MAX_BACKOFF: Duration = Duration::from_secs(8);

/// The configuration for re-attempting failed HTTP requests.
///
/// By default, this is configured to:
/// * `max_attempts`: [`DEFAULT_MAX_ATTEMPTS`]
/// * `use_jitter`: [`DEFAULT_USE_JITTER`]
/// * `policy`: Exponential
///    * Base: [`DEFAULT_BASE`],
///    * Factor: [`DEFAULT_FACTOR`]
///    * Maximum: [`DEFAULT_MAX_BACKOFF`]
pub struct RetryConfig {
    pub max_attempts: usize,
    pub use_jitter: bool,
    pub policy: RetryPolicy,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: DEFAULT_MAX_ATTEMPTS,
            use_jitter: DEFAULT_USE_JITTER,
            policy: RetryPolicy::Exponential {
                base: DEFAULT_BASE,
                factor: DEFAULT_FACTOR,
                maximum: DEFAULT_MAX_BACKOFF,
            },
        }
    }
}

/// An iterator of exponentially growing values.
///
/// If `jitter` is used, a uniformly random number up to 50% of the base will be added.
///
/// For most practical uses, this is unbounded, however it will return `None` if it reaches the maximum `f32`.
pub struct ExponentialBackoff {
    current: Duration,
    factor: f32,
}

impl ExponentialBackoff {
    pub fn new(base: Duration, factor: f32) -> Self {
        Self {
            current: base,
            factor,
        }
    }
}

impl Iterator for ExponentialBackoff {
    type Item = Duration;

    fn next(&mut self) -> Option<Self::Item> {
        let next_val = self.current.as_secs_f32() * self.factor;
        if f32::is_finite(next_val) {
            self.current = Duration::from_secs_f32(next_val);
            Some(self.current)
        } else {
            None
        }
    }
}

/// An iterator that takes an underlying iterator of [`Duration`] and for each item, adds up to 50%
/// of the duration to the base.
struct Jitter<T: Iterator<Item = Duration>>(T);

impl<T: Iterator<Item = Duration>> Jitter<T> {
    fn new(inner: T) -> Jitter<T> {
        Jitter(inner)
    }

    /// A random number between 0 and 1 using a simple xorshift algorithm on the system nanosecond time.
    /// While not "high quality" randomness, it's good enough for jitter.
    fn xorshift_rand() -> f32 {
        /// u32 xorshift from Marsaglia's "Xorshift RNGs"
        fn xorshift(mut state: u32) -> u32 {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state
        }
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u32;
        (xorshift(nanos) as f32) / (u32::MAX as f32)
    }
}

impl<T: Iterator<Item = Duration>> Iterator for Jitter<T> {
    type Item = Duration;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(|duration| {
            let duration = duration.as_secs_f32();
            let jitter = Self::xorshift_rand() * (duration / 2.0);
            Duration::from_secs_f32(duration + jitter)
        })
    }
}

impl RetryConfig {
    /// Returns a function that will generate a [`Duration`] iterator that implements this policy.
    pub fn to_backoff_generator(&self) -> Box<DynFnBackoffGenerator> {
        let max_attempts = self.max_attempts;
        let jitter = self.use_jitter;
        match self.policy {
            RetryPolicy::Exponential {
                base,
                factor,
                maximum: max_delay,
            } => {
                let generator = move || {
                    Self::boxed_iterator(
                        ExponentialBackoff::new(base, factor)
                            .map(move |backoff| max_delay.min(backoff))
                            .take(max_attempts),
                        jitter,
                    )
                };
                Box::new(generator)
            }
            RetryPolicy::Fixed { duration } => {
                let generator = move || {
                    Self::boxed_iterator(std::iter::repeat(duration).take(max_attempts), jitter)
                };
                Box::new(generator)
            }
        }
    }

    fn boxed_iterator<T: Iterator<Item = Duration> + 'static>(
        iter: T,
        use_jitter: bool,
    ) -> Box<dyn Iterator<Item = Duration>> {
        let boxed: Box<dyn Iterator<Item = Duration>> = if use_jitter {
            Box::new(Jitter(iter))
        } else {
            Box::new(iter)
        };
        boxed
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum RetryPolicy {
    Exponential {
        base: Duration,
        factor: f32,
        maximum: Duration,
    },
    Fixed {
        duration: Duration,
    },
}

type DynFnResponseParser = dyn Fn(&Result<ureq::Response, ureq::Error>) -> NextAction;
/// A function that generates an Iterator of [`Duration`] representing a [`RetryPolicy`]
type DynFnBackoffGenerator = dyn Fn() -> Box<dyn Iterator<Item = Duration>>;

type RateLimiter<T> = governor::RateLimiter<
    governor::state::NotKeyed,
    governor::state::InMemoryState,
    T,
    NoOpMiddleware<<T as Clock>::Instant>,
>;

pub struct HttpValidator<T: Clock> {
    validator_id: ValidatorId,
    /// The maximum time allowed for a single validation attempt, inclusive of rate-limiting and retry delay.
    max_attempt_duration: Duration,
    rule_id: RuleId,
    attempted_cache: Arc<Mutex<HashSet<[u8; 32]>>>,
    clock: T,
    rate_limiter: Arc<RateLimiter<T>>,
    request_generator: RequestGenerator,
    response_parser: Box<DynFnResponseParser>,
    backoff_generator: Box<DynFnBackoffGenerator>,
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
    add_headers: Box<dyn Fn(&Candidate, ureq::Request) -> ureq::Request>,
    build_post_payload: Option<Box<DynFnPostPayloadGenerator>>,
}

/// A wrapper around [`thread::sleep`](std::thread::sleep) that advances a [`MockClock`](crate::common::time::MockClock)
/// when running tests.
fn thread_sleep(duration: Duration) {
    #[cfg(test)]
    time::MockClock::advance(duration);
    #[cfg(not(test))]
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

        let retry_delays = (self.backoff_generator)();
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
            request = (self.request_generator.add_headers)(&candidate, request);

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

const DEFAULT_REQ_PER_SECOND: u32 = 50;

/// The limit to instantiate the rate limiter with.
///
/// Defaults to [`DEFAULT_REQ_PER_SECOND`] requests per second.
#[derive(Debug, Clone)]
struct RateLimitQuota(governor::Quota);
impl Default for RateLimitQuota {
    fn default() -> Self {
        Self(governor::Quota::per_second(
            NonZeroU32::new(DEFAULT_REQ_PER_SECOND).unwrap(),
        ))
    }
}

pub struct HttpValidatorBuilder {
    validator_id: ValidatorId,
    max_attempted_duration: Duration,
    rule_id: RuleId,
    request_generator: RequestGenerator,
    response_parser: Box<DynFnResponseParser>,
    rate_limit: RateLimitQuota,
    retry_config: RetryConfig,
}

impl HttpValidatorBuilder {
    pub fn new(
        validator_id: ValidatorId,
        rule_id: RuleId,
        request_generator: RequestGenerator,
        response_parser: Box<DynFnResponseParser>,
    ) -> Self {
        Self {
            validator_id,
            max_attempted_duration: Duration::from_secs(15),
            rule_id,
            request_generator,
            response_parser,
            rate_limit: RateLimitQuota::default(),
            retry_config: RetryConfig::default(),
        }
    }

    pub fn retry_config(mut self, config: RetryConfig) -> Self {
        self.retry_config = config;
        self
    }

    /// Configures the rate limiter's max burst rate.
    ///
    /// # Panics
    /// Panics if the rate is under 1 unit per second, or if `units` or `interval` are zero.
    pub fn rate_limit(mut self, units: u32, interval: Duration) -> Self {
        let units_per_second = units as f32 / interval.as_secs_f32();
        let units = NonZeroU32::new(units_per_second as u32)
            .expect("caller should pass in non-zero number");
        self.rate_limit = RateLimitQuota(governor::Quota::per_second(units));
        self
    }

    /// The maximum amount of time to spend on a single validation attempt, inclusive of retries and
    /// round-trip latency.
    pub fn max_attempt_duration(mut self, max: Duration) -> Self {
        self.max_attempted_duration = max;
        self
    }

    pub fn build(self) -> HttpValidator<DefaultClock> {
        let clock = DefaultClock::default();
        self.build_with_clock(clock)
    }

    /// Builds the [`HttpValidator`] with a [`time::MockClock`].
    #[cfg(test)]
    fn build_for_test(self) -> HttpValidator<time::MockClock> {
        let clock = time::MockClock;
        self.build_with_clock(clock)
    }

    /// Builds the `HttpValidator` with the given clock.
    fn build_with_clock<T: Clock>(self, clock: T) -> HttpValidator<T> {
        let rate_limiter = RateLimiter::direct_with_clock(self.rate_limit.0, &clock);
        HttpValidator {
            validator_id: self.validator_id,
            max_attempt_duration: self.max_attempted_duration,
            rule_id: self.rule_id,
            attempted_cache: Arc::new(Mutex::new(HashSet::new())),
            clock,
            rate_limiter: Arc::new(rate_limiter),
            request_generator: self.request_generator,
            response_parser: self.response_parser,
            backoff_generator: self.retry_config.to_backoff_generator(),
        }
    }
}

#[allow(clippy::type_complexity)]
pub struct RequestGeneratorBuilder {
    agent: ureq::Agent,
    method: HttpMethod,
    format_url: Box<dyn Fn(&Candidate) -> String>,
    add_header_fns: Vec<Box<dyn Fn(&Candidate, ureq::Request) -> ureq::Request>>,
    build_post_payload: Option<Box<DynFnPostPayloadGenerator>>,
}

impl RequestGeneratorBuilder {
    /// Creates a new builder for an HTTP GET request generator.
    pub fn http_get(
        agent: ureq::Agent,
        url_generator: Box<dyn Fn(&Candidate) -> String>,
    ) -> RequestGeneratorBuilder {
        RequestGeneratorBuilder {
            agent,
            method: HttpMethod::Get,
            format_url: url_generator,
            add_header_fns: Vec::new(),
            build_post_payload: None,
        }
    }

    /// Creates a new builder for an HTTP POST request generator.
    pub fn http_post(
        agent: ureq::Agent,
        url_generator: Box<dyn Fn(&Candidate) -> String>,
        payload_generator: Option<Box<DynFnPostPayloadGenerator>>,
    ) -> RequestGeneratorBuilder {
        RequestGeneratorBuilder {
            agent,
            method: HttpMethod::Post,
            format_url: url_generator,
            add_header_fns: Vec::new(),
            build_post_payload: payload_generator,
        }
    }

    /// Adds a header with a constant value to the HTTP request.
    pub fn header(mut self, header: impl Into<String>, value: impl Into<String>) -> Self {
        let (header, value) = (header.into(), value.into());
        let add_header = move |_c: &Candidate, mut req: ureq::Request| -> ureq::Request {
            req = req.set(header.as_str(), value.as_str());
            req
        };
        self.add_header_fns.push(Box::new(add_header));
        self
    }

    /// Adds a header with a value based on the [`Candidate`] to the HTTP request.
    pub fn dynamic_header(
        mut self,
        header: impl Into<String>,
        value_generator: Box<dyn Fn(&Candidate) -> String>,
    ) -> Self {
        let header = header.into();
        let add_header = move |cand: &Candidate, mut req: ureq::Request| -> ureq::Request {
            let value = value_generator(cand);
            req = req.set(&header, value.as_str());
            req
        };
        self.add_header_fns.push(Box::new(add_header));
        self
    }
}

impl RequestGeneratorBuilder {
    pub fn build(self) -> RequestGenerator {
        let header_fns = self.add_header_fns;
        let add_headers =
            move |candidate: &Candidate, mut request: ureq::Request| -> ureq::Request {
                for header_fn in &header_fns {
                    request = header_fn(candidate, request);
                }
                request
            };
        RequestGenerator {
            agent: self.agent,
            method: self.method,
            format_url: self.format_url,
            add_headers: Box::new(add_headers),
            build_post_payload: self.build_post_payload,
        }
    }
}

/// The default duration to wait when failing to parse an expected "Retry-After" header.
const DEFAULT_RETRY_AFTER: Duration = Duration::from_secs(2);

/// Builds a generalized Response parser that only looks at HTTP status codes.
///
/// When a transport error occurs, the original request will be retried if it was due to a
/// network error (not an incorrectly-formatted request)
pub struct ResponseParserBuilder(Vec<Box<DynFnResponseParser>>);

impl ResponseParserBuilder {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    /// Provides a simple inspection of the HTTP response's status code, using the specified
    /// `NextAction` upon match.
    ///
    /// Note: response parsers are evaluated in the order they are inserted into the builder.
    pub fn on_status_code(mut self, target_code: u16, next_action: NextAction) -> Self {
        let handler = move |res: &Result<ureq::Response, ureq::Error>| -> NextAction {
            let response_code = match res.as_ref() {
                Ok(response) => Some(response.status()),
                Err(ureq::Error::Status(status, _)) => Some(*status),
                _ => None,
            };
            if response_code.is_some_and(|resp_code| resp_code == target_code) {
                next_action
            } else {
                NextAction::Unhandled
            }
        };
        self.0.push(Box::new(handler));
        self
    }

    pub fn build(mut self) -> Box<DynFnResponseParser> {
        self.0.push(Self::default_err_handler());
        let handlers = self.0;
        let sequential = move |res: &Result<ureq::Response, ureq::Error>| -> NextAction {
            for handler in &handlers {
                let next_action = handler(res);
                if next_action != NextAction::Unhandled {
                    return next_action;
                }
            }
            NextAction::Unhandled
        };
        Box::new(sequential)
    }

    /// Builds a default handler for errors.
    fn default_err_handler() -> Box<DynFnResponseParser> {
        let handler = |res: &Result<ureq::Response, ureq::Error>| -> NextAction {
            match res.as_ref() {
                Ok(_) => NextAction::Unhandled,
                Err(err) => match err {
                    ureq::Error::Status(code, response) => match code {
                        429 => {
                            let retry_after = response.header("Retry-After").map(str::parse::<u64>);
                            if let Some(Ok(retry_after)) = retry_after {
                                NextAction::RetryAfter(Duration::from_secs(retry_after))
                            } else {
                                NextAction::RetryAfter(DEFAULT_RETRY_AFTER)
                            }
                        }
                        500 | 502 | 503 | 504 => NextAction::Retry,
                        501 | 506 | 507 | 508 | 510 | 511 => NextAction::Abort,
                        _ => NextAction::Unhandled,
                    },
                    ureq::Error::Transport(transport) => match transport.kind() {
                        ureq::ErrorKind::Dns
                        | ureq::ErrorKind::ConnectionFailed
                        | ureq::ErrorKind::Io
                        | ureq::ErrorKind::ProxyConnect => NextAction::Retry,
                        _ => NextAction::Abort,
                    },
                },
            }
        };
        Box::new(handler)
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
