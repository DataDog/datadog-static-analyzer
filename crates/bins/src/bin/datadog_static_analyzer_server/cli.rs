use getopts::{Fail, Options};
use kernel::constants::{CARGO_VERSION, VERSION};
use rocket::tokio::sync::mpsc::{channel, Sender};
use rocket::tokio::time::sleep;
use rocket::{Build, Rocket, Shutdown};
use std::path::PathBuf;
use std::time::Duration;
use std::{env, process, thread};
use thiserror::Error;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_appender::rolling::RollingFileAppender;
use tracing_subscriber::EnvFilter;

use super::state::ServerState;
use super::utils::get_current_timestamp_ms;

fn print_usage(program: &str, opts: &Options) {
    let brief = format!("Usage: {} [options]", program);
    print!("{}", opts.usage(&brief));
}

fn get_opts() -> Options {
    let mut opts = Options::new();
    opts.optopt(
        "s",
        "static",
        "directory for static files",
        "/path/to/directory",
    );
    opts.optopt("p", "port", "port to run the server on", "8000");
    opts.optopt("a", "address", "address to listen on", "127.0.0.1");
    opts.optopt(
        "k",
        "keep-alive-timeout",
        "how many seconds without a request the server will exit",
        "90",
    );
    opts.optflag("e", "enable-shutdown", "enables the shutdown endpoint");
    opts.optflag("h", "help", "print this help");
    opts.optflag("v", "version", "shows the tool version");
    opts.optopt(
        "l",
        "logs",
        "Enables log rotation and saves logs to a file in a system temp folder. Options: minutely, hourly, daily",
        "[minutely, hourly, daily]",
    );

    // TODO (JF): Remove this when releasing 0.3.8
    opts.optflag("", "ddsa-runtime", "(deprecated)");
    opts
}

fn get_log_dir() -> PathBuf {
    let path = "static-analysis-server/logs";
    #[cfg(unix)]
    {
        PathBuf::from(format!("/tmp/{path}"))
    }
    #[cfg(windows)]
    {
        let mut log_dir = std::env::var("TEMP")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                // Fallback in case TEMP is not set
                PathBuf::from("C:\\Temp")
            });
        log_dir.push(path);
        log_dir
    }
}

#[derive(Debug, Error)]
pub enum CliError {
    #[error("Error parsing arguments: {0:?}")]
    Parsing(#[from] Fail),
    #[error("Invalid port argument {0:?}. It must be a number.")]
    InvalidPort(String),
    #[error("Invalid address argument {0:?}.")]
    InvalidAddress(String),
    #[error("Invalid log argument: {0}. It must be 'minutely', 'hourly' or 'daily'.")]
    InvalidLogRolling(String),
}

fn try_to_file_appender(
    value: String,
    log_dir: PathBuf,
    file_name_prefix: String,
) -> Result<RollingFileAppender, CliError> {
    match value.to_lowercase().as_ref() {
        "minutely" => Ok(tracing_appender::rolling::minutely(
            log_dir,
            file_name_prefix,
        )),
        "hourly" => Ok(tracing_appender::rolling::hourly(log_dir, file_name_prefix)),
        "daily" => Ok(tracing_appender::rolling::daily(log_dir, file_name_prefix)),
        _ => Err(CliError::InvalidLogRolling(value)),
    }
}

pub enum RocketPreparation {
    ServerInfo {
        rocket: Box<Rocket<Build>>,
        state: ServerState,
        tx_rocket_shutdown: rocket::tokio::sync::mpsc::Sender<Shutdown>,
        guard: Option<WorkerGuard>,
    },
    NoServerInteraction,
}

/// Prepares the rocket and sets the configuration and the shared state.
///
/// # Panics
///
/// This function can panic or end the process in the case keep-alive is on and:
/// -  graceful exit doesn't work (abort)
///
pub fn prepare_rocket(tx_keep_alive_error: Sender<i32>) -> Result<RocketPreparation, CliError> {
    let args: Vec<String> = env::args().collect();
    let program = &args[0];
    let opts = get_opts();

    let matches = opts.parse(&args[1..])?;

    if matches.opt_present("v") {
        println!("Version: {}, revision: {}", CARGO_VERSION, VERSION);
        return Ok(RocketPreparation::NoServerInteraction);
    }

    if matches.opt_present("h") {
        print_usage(program, &opts);
        return Ok(RocketPreparation::NoServerInteraction);
    }

    // initialize the tracing subscriber here as we're only interested in the server logs not the other CLI instructions
    let guard = if let Some(log_rolling) = matches.opt_str("l") {
        // tracing with logs
        let log_dir = get_log_dir();
        let file_appender = try_to_file_appender(
            log_rolling,
            log_dir,
            format!("server.{}.log", std::process::id()),
        )?;
        let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .json()
            .with_writer(non_blocking)
            .init();
        Some(guard)
    } else {
        // regular tracing subscriber
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .init();
        None
    };

    // server state
    tracing::debug!("Preparing the server state and rocket configuration");
    let mut server_state = ServerState::new(matches.opt_str("s"), matches.opt_present("e"));
    let mut rocket_configuration = rocket::config::Config {
        // disable rocket colors and emojis if we're logging to a file as we will be using json format
        cli_colors: !matches.opt_present("l"),
        ..Default::default()
    };

    // set up the port if present
    if let Some(port_str) = matches.opt_str("p") {
        rocket_configuration.port = match port_str.parse::<u16>() {
            Ok(port) => port,
            Err(e) => {
                tracing::error!(error=?e, port=port_str, "Error trying to parse the address");
                return Err(CliError::InvalidPort(port_str));
            }
        };
        tracing::debug!("Port set to {port_str}");
    }

    // set up the address if present
    if let Some(addr) = matches.opt_str("a") {
        rocket_configuration.address = match addr.parse() {
            Ok(parsed_addr) => parsed_addr,
            Err(e) => {
                tracing::error!(error=?e, address=addr, "Error trying to parse the address");
                return Err(CliError::InvalidAddress(addr));
            }
        };
        tracing::debug!("Address set to {addr}");
    }

    // TODO: should this be removed already?
    if matches.opt_present("ddsa-runtime") {
        println!("[WARNING] the --ddsa-runtime flag is deprecated and will be removed in the next version");
    }

    // channel used to send the shutdown handler so that we can exit the server gracefully
    let (tx_rocket_shutdown, mut rx_rocket_shutdown) = channel::<Shutdown>(1);

    // if we set up the keepalive mechanism (option -k)
    //   1. Get the timeout value as parameter
    //   2. Start the thread that checks every 5 seconds if we should exit the server
    if matches.opt_present("k") {
        if let Some(timeout_sec) = matches.opt_str("k").and_then(|k| k.parse::<u128>().ok()) {
            tracing::info!("Keep alive is set to {timeout_sec} seconds");
            // this will ensure that the keep-alive fairing is added, which is going to be the one
            // updating the `last_ping_request_timestamp_ms`.
            server_state.is_keepalive_enabled = true;

            let timeout_ms = timeout_sec * 1000;
            let last_ping_request_timestamp_ms =
                server_state.last_ping_request_timestamp_ms.clone();

            // thread that periodically checks if we should exit the server
            rocket::tokio::spawn(async move {
                if let Some(shutdown_handle) = rx_rocket_shutdown.recv().await {
                    tracing::info!("Starting the keep alive loop");

                    loop {
                        // get the latest request timestamp and the current one
                        // remember that the `last_ping_request_timestamp_ms` state will be written by a fairing on every successful request
                        let latest_timestamp = last_ping_request_timestamp_ms
                            .try_read()
                            .map(|x| *x)
                            .unwrap_or_default();

                        let current_timestamp = get_current_timestamp_ms();

                        if latest_timestamp > 0 && current_timestamp > latest_timestamp + timeout_ms
                        {
                            tracing::info!("Exiting because of timeout. Trying to exit gracefully");
                            shutdown_handle.notify();
                            // we give 10 seconds for the process to terminate
                            // if it does not, we abort
                            sleep(Duration::from_secs(10)).await;
                            tracing::error!(
                                "No graceful exit on first attempt. Trying another channel"
                            );
                            // signal the main thread to kill itself. wait for 10 secs and use abort if needed.
                            let _ = tx_keep_alive_error.send(101).await;
                            thread::sleep(Duration::from_secs(10));
                            tracing::error!(
                                "No graceful exit on suicide channel.  Aborting the process"
                            );
                            process::abort();
                        }
                        thread::sleep(Duration::from_secs(5));
                    }
                } else {
                    tracing::error!("CRITICAL: The channel has disconnected");
                    // if the channel dies we're going to exit the process with a custom error code.
                    let _ = tx_keep_alive_error.send(100).await;
                };
            });
        }
    }

    let state = server_state.clone();
    let rocket = rocket::custom(rocket_configuration).manage(state);

    Ok(RocketPreparation::ServerInfo {
        rocket: Box::new(rocket),
        state: server_state,
        tx_rocket_shutdown,
        guard,
    })
}
