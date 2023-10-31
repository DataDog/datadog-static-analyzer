use rocket::{
    fairing::{Fairing, Info, Kind},
    http::Header,
    Data, Request, Response, State,
};
use server::constants::{
    SERVER_HEADER_KEEPALIVE_ENABLED, SERVER_HEADER_SERVER_REVISION, SERVER_HEADER_SERVER_VERSION,
    SERVER_HEADER_SHUTDOWN_ENABLED,
};

use super::{
    endpoints::{get_revision, get_version},
    state::ServerState,
    utils::get_current_timestamp_ms,
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
