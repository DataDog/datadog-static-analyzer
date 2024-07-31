use rocket::request::{FromRequest, Outcome};
use rocket::{
    fairing::{Fairing, Info, Kind},
    http::Header,
    Data, Request, Response, State,
};
use server::constants::{
    SERVER_HEADER_KEEPALIVE_ENABLED, SERVER_HEADER_SERVER_REVISION, SERVER_HEADER_SERVER_VERSION,
    SERVER_HEADER_SHUTDOWN_ENABLED,
};
use tracing::Span;
use uuid::Uuid;

use super::{
    state::ServerState, utils::get_current_timestamp_ms, utils::get_revision, utils::get_version,
};

pub struct Cors;

// Adding CORS for the server.
// See https://stackoverflow.com/questions/62412361/how-to-set-up-cors-or-options-for-rocket-rs
// for more information.
#[rocket::async_trait]
impl Fairing for Cors {
    fn info(&self) -> Info {
        Info {
            name: "Add CORS headers to responses",
            kind: Kind::Response,
        }
    }

    async fn on_response<'r>(&self, _request: &'r Request<'_>, response: &mut Response<'r>) {
        response.set_header(Header::new("Access-Control-Allow-Origin", "*"));
        response.set_header(Header::new(
            "Access-Control-Allow-Methods",
            "POST, GET, PATCH, OPTIONS",
        ));
        response.set_header(Header::new("Access-Control-Allow-Headers", "*"));
        response.set_header(Header::new("Access-Control-Allow-Credentials", "true"));
    }
}

pub struct CustomHeaders;

#[rocket::async_trait]
impl Fairing for CustomHeaders {
    fn info(&self) -> Info {
        Info {
            name: "Custom Headers",
            kind: Kind::Response,
        }
    }

    async fn on_response<'r>(&self, request: &'r Request<'_>, response: &mut Response<'r>) {
        let state = request.guard::<&State<ServerState>>().await;

        if let rocket::outcome::Outcome::Success(state) = state {
            response.set_header(Header::new(
                SERVER_HEADER_SHUTDOWN_ENABLED,
                state.is_shutdown_enabled.to_string(),
            ));
            response.set_header(Header::new(
                SERVER_HEADER_KEEPALIVE_ENABLED,
                state.is_keepalive_enabled.to_string(),
            ));
        }

        response.set_header(Header::new(SERVER_HEADER_SERVER_VERSION, get_version()));
        response.set_header(Header::new(SERVER_HEADER_SERVER_REVISION, get_revision()));
    }
}

pub struct KeepAlive;

#[rocket::async_trait]
impl Fairing for KeepAlive {
    fn info(&self) -> Info {
        Info {
            name: "Keep Alive",
            kind: Kind::Request,
        }
    }

    async fn on_request(&self, request: &mut Request<'_>, _data: &mut Data<'_>) {
        let state = request.guard::<&State<ServerState>>().await;

        if let rocket::outcome::Outcome::Success(state) = state {
            // the fairing shouldn't be added if keep alive is not enabled but just playing defensive here
            if state.is_keepalive_enabled {
                // mutate the keep alive ms
                if let Ok(mut x) = state.last_ping_request_timestamp_ms.try_write() {
                    *x = get_current_timestamp_ms();
                }
            }
        }
    }
}

/// Provides functionality to associate a `UUIDv4` per request.
///
/// Rocket 0.5.0 does not generate per-request IDs (see: [#21](https://github.com/rwf2/Rocket/issues/21))
/// Until upstream natively supports this, we use a custom [Fairing] to generate one.
pub struct TracingFairing;

/// A per-request struct wrapping a [Span].
//
// Note: We need to expose the Span's `enter` function manually because Rocket's API does not support the `tracing` crate.
// Thus, every route that wants to have a trace span and request ID will need to use this struct.
pub struct TraceSpan {
    span: Span,
    /// An HTTP request id.
    ///
    /// Note: This could either be an arbitrary user-supplied string or auto-generated as a UUID v4
    #[allow(dead_code)]
    pub request_id: String,
}

impl TraceSpan {
    /// Calls [enter][tracing::span::Span::enter] on the underlying [Span]
    pub fn enter(&self) -> tracing::span::Entered<'_> {
        self.span.enter()
    }
}

/// A newtype Option representing a [Span] that is used to conform to the [`Request::local_cache`] API
struct FairingTraceSpan(Option<Span>);

/// A newtype Option representing a [String] request ID that is used to conform to the [`Request::local_cache`] API
struct FairingRequestId(Option<String>);

#[rocket::async_trait]
impl Fairing for TracingFairing {
    fn info(&self) -> Info {
        Info {
            name: "Trace Span",
            kind: Kind::Request | Kind::Response,
        }
    }

    async fn on_request(&self, req: &mut Request<'_>, _data: &mut Data<'_>) {
        let request_id = req
            .headers()
            .get_one("X-Request-Id")
            .map_or_else(|| Uuid::new_v4().to_string(), String::from);

        let request_span = tracing::info_span!(
            "http_request",
            "http.request_id" = request_id.as_str(),
            "http.method" = req.method().as_str(),
            "http.uri" = req.uri().path().as_str(),
            "http.status_code" = tracing::field::Empty
        );

        let _ = req.local_cache(|| FairingRequestId(Some(request_id)));
        let _ = req.local_cache(|| FairingTraceSpan(Some(request_span)));
    }

    async fn on_response<'r>(&self, req: &'r Request<'_>, res: &mut Response<'r>) {
        let span = req
            .local_cache(|| FairingTraceSpan(None))
            .0
            .clone()
            .expect("Span should be instantiated by on_request");
        let span = span.entered();
        span.record("http.status_code", res.status().code);

        let request_id = req
            .local_cache(|| FairingRequestId(None))
            .0
            .as_deref()
            .expect("Request id should be instantiated by on_request");

        res.set_header(Header::new("X-Request-Id", request_id));
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for TraceSpan {
    type Error = ();

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let request_id = req
            .local_cache(|| FairingRequestId(None))
            .0
            .clone()
            .expect("Span should be instantiated by on_request");
        let span = req
            .local_cache(|| FairingTraceSpan(None))
            .0
            .clone()
            .expect("Span should be instantiated by on_request");

        Outcome::Success(Self { span, request_id })
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use rocket::config::LogLevel::Off;
    use rocket::local::blocking::Client;
    use rocket::{Build, Config, Rocket};

    fn silent_rocket() -> Rocket<Build> {
        let config = Config {
            log_level: Off,
            ..Config::default()
        };
        rocket::custom(&config)
    }

    /// Tests that TracingFairing echoes any X-Request-Id passed in
    #[test]
    fn echo_request_id() {
        let passed_in_id = "1+2+3+4+5+6+7+8+9+10";
        let rocket = silent_rocket().attach(TracingFairing);

        let client = Client::tracked(rocket).unwrap();
        let req = client
            .get("/")
            .header(Header::new("X-Request-Id", passed_in_id));
        let response = req.dispatch();
        assert_eq!(
            response.headers().get_one("X-Request-Id"),
            Some(passed_in_id)
        )
    }

    /// Tests that TracingFairing generates a UUID v4 if X-Request-Id isn't specified
    #[test]
    fn auto_generates_missing_request_id() {
        let rocket = silent_rocket().attach(TracingFairing);
        let client = Client::tracked(rocket).unwrap();
        let req = client.get("/");
        let response = req.dispatch();
        let returned_uuid_request_id = response
            .headers()
            .get_one("X-Request-Id")
            .map(|value| Uuid::parse_str(value).is_ok())
            .unwrap_or(false);
        assert!(returned_uuid_request_id);
    }
}
