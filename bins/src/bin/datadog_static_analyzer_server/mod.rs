mod cli;
mod endpoints;
mod fairings;
mod state;
mod utils;

pub async fn start() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    // prepare the rocket based on the cli args.
    // NOTE: shared state is already managed by the rocket. No need to use `manage` again.
    // we get the state back just in case we want to add a particular fairing based on it.
    let (mut rocket, state, tx_shutdown) = cli::prepare_rocket();
    // set fairings
    rocket = rocket
        .attach(fairings::Cors)
        .attach(fairings::CustomHeaders);
    if state.is_keepalive_enabled {
        rocket = rocket.attach(fairings::KeepAlive);
    }
    // launch the rocket
    if let Err(e) = endpoints::launch_rocket_with_endpoints(rocket, tx_shutdown).await {
        panic!("Something went wrong while trying to ignite the rocket {e:?}");
    }
}
