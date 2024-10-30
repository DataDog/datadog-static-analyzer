use std::process;

use cli::{CliError, RocketPreparation};
use tracing_subscriber::EnvFilter;

mod cli;
mod endpoints;
mod fairings;
mod ide;
mod state;
mod utils;

/// Starts the process
///
/// # Panics
///
/// This function will exit the process when it finds an error.
pub async fn start() {
    // TODO: (ROB) we only want to instrument the server here
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    // prepare the rocket based on the cli args.
    // NOTE: shared state is already managed by the rocket. No need to use `manage` again.
    // we get the state back just in case we want to add a particular fairing based on it.
    let rocket_preparation = cli::prepare_rocket();
    match rocket_preparation {
        Err(e) => {
            eprintln!("Error found: {e}");
            match e {
                CliError::Parsing(_f) => process::exit(22), // invalid argument code
                CliError::InvalidPort(_port) => process::exit(1), // generic error code
            }
        }
        Ok(RocketPreparation::NoServerInteraction) => {
            // don't do anything, just exit with 0 code
        }
        Ok(RocketPreparation::ServerInfo {
            mut rocket,
            state,
            tx_shutdown,
        }) => {
            // set fairings
            rocket = rocket
                .attach(fairings::Cors)
                .attach(fairings::CustomHeaders)
                .attach(fairings::TracingFairing);
            if state.is_keepalive_enabled {
                rocket = rocket.attach(fairings::KeepAlive);
            }
            // launch the rocket
            if let Err(e) = endpoints::launch_rocket_with_endpoints(rocket, tx_shutdown).await {
                // TODO: (ROB) drop guard
                panic!("Something went wrong while trying to ignite the rocket {e:?}");
            }
        }
    }
}
