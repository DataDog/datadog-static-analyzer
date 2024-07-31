mod datadog_static_analyzer_server;

#[rocket::main]
async fn main() {
    datadog_static_analyzer_server::start().await;
}
