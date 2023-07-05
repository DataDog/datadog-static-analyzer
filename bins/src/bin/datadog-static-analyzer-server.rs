use kernel::constants::VERSION;
use rocket::fairing::{Fairing, Info, Kind};
use rocket::http::Header;
use rocket::serde::json::{json, Json, Value};
use rocket::{Request as RocketRequest, Response};
use server::model::request::Request;
use server::server::process_request;

pub struct CORS;

// Adding CORS for the server.
// See https://stackoverflow.com/questions/62412361/how-to-set-up-cors-or-options-for-rocket-rs
// for more information.
#[rocket::async_trait]
impl Fairing for CORS {
    fn info(&self) -> Info {
        Info {
            name: "Add CORS headers to responses",
            kind: Kind::Response,
        }
    }

    async fn on_response<'r>(&self, _request: &'r RocketRequest<'_>, response: &mut Response<'r>) {
        response.set_header(Header::new("Access-Control-Allow-Origin", "*"));
        response.set_header(Header::new(
            "Access-Control-Allow-Methods",
            "POST, GET, PATCH, OPTIONS",
        ));
        response.set_header(Header::new("Access-Control-Allow-Headers", "*"));
        response.set_header(Header::new("Access-Control-Allow-Credentials", "true"));
    }
}

#[rocket::post("/analyze", format = "application/json", data = "<request>")]
fn analyze(request: Json<Request>) -> Value {
    json!(process_request(request.into_inner()))
}

#[rocket::get("/version", format = "text/html")]
fn get_version() -> String {
    VERSION.to_string()
}

#[rocket::get("/ping", format = "text/html")]
fn ping() -> String {
    "pong".to_string()
}

/// Catches all OPTION requests in order to get the CORS related Fairing triggered.
#[rocket::options("/<_..>")]
fn get_options() -> String {
    /* Intentionally left empty */
    "".to_string()
}

#[rocket::launch]
fn rocket_main() -> _ {
    rocket::build()
        .attach(CORS)
        .mount("/", rocket::routes![analyze])
        .mount("/", rocket::routes![get_version])
        .mount("/", rocket::routes![ping])
        .mount("/", rocket::routes![get_options])
}
