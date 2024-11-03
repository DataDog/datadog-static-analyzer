use std::process;

use cli::{CliError, RocketPreparation};
use endpoints::EndpointError;
use error_codes::{
    ERROR_BAD_ADDRESS, ERROR_CHANNEL_SENDER_DROPPED, ERROR_GENERAL, ERROR_INVALID_ARGUMENT,
};
use rocket::tokio::sync::mpsc::channel;

mod cli;
mod endpoints;
mod error_codes;
mod fairings;
mod ide;
mod state;
mod utils;

/// Starts the process
///
/// # Panics
///
/// This function will exit the process and panic when it finds an error.
pub async fn start() {
    let (tx_keep_alive_error, mut rx_keep_alive_error) = channel::<i32>(1);

    // prepare the rocket based on the cli args.
    // NOTE: shared state is already managed by the rocket. No need to use `manage` again.
    // we get the state back just in case we want to add a particular fairing based on it.
    // IMPORTANT: we're passing a clone of the tx as we want to keep a reference in the
    // main thread to avoid the rx from returning None if the tx is dropped in cli::prepare_rocket.
    // This will happen for sure in case the keep-alive mechanism is not enabled.
    // Just by keeping the reference in here, we are good.
    let rocket_preparation = cli::prepare_rocket(tx_keep_alive_error.clone());
    match rocket_preparation {
        Err(e) => {
            eprintln!("Error found: {e}");
            match e {
                CliError::Parsing(_) => process::exit(ERROR_INVALID_ARGUMENT),
                _ => process::exit(ERROR_GENERAL),
            }
        }
        Ok(RocketPreparation::NoServerInteraction) => {
            // don't do anything, just exit with 0 code
        }
        Ok(RocketPreparation::ServerInfo {
            mut rocket,
            state,
            tx_rocket_shutdown,
            guard,
        }) => {
            // set fairings
            *rocket = rocket
                .attach(fairings::Cors)
                .attach(fairings::CustomHeaders)
                .attach(fairings::TracingFairing);
            if state.is_keepalive_enabled {
                *rocket = rocket.attach(fairings::KeepAlive);
            }

            // launch the rocket and check if we receive a keep-alive error
            let result = rocket::tokio::select! {
                a = endpoints::launch_rocket_with_endpoints(*rocket, tx_rocket_shutdown) => a,
                b = rx_keep_alive_error.recv() => match b {
                    Some(c) => Err(c.into()),
                    _ => Err(EndpointError::ExitCode(ERROR_CHANNEL_SENDER_DROPPED))
                },
            };

            if let Err(e) = result {
                let error_str = format!("{e:?}");

                tracing::error!(
                    "Something went wrong while trying to ignite the rocket: {error_str}"
                );
                // flushing the pending logs by dropping the guard before panic
                drop(guard);

                match e {
                    EndpointError::ExitCode(code) => process::exit(code),
                    EndpointError::RocketError(re) => {
                        if let rocket::error::ErrorKind::Bind(_) = re.kind() {
                            process::exit(ERROR_BAD_ADDRESS);
                        }
                    }
                    _ => (),
                }

                panic!("Something went wrong while trying to ignite the rocket {error_str}");
            }
        }
    }
}
