use getopts::{Fail, Options};
use kernel::constants::{CARGO_VERSION, VERSION};
use rocket::{Build, Rocket, Shutdown};
use std::path::PathBuf;
use std::sync::mpsc::{channel, Sender};
use std::sync::Arc;
use std::time::Duration;
use std::{env, process, thread};
use thiserror::Error;
use tracing_appender::non_blocking::WorkerGuard;
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
    opts.optflag(
        "l",
        "logs",
        "Enables logs to a file. Usually /tmp/static-analyzer-server/logs",
    );
    // TODO (JF): Remove this when releasing 0.3.8
    opts.optflag("", "ddsa-runtime", "(deprecated)");
    opts
}

fn get_log_dir() -> PathBuf {
    let mut log_dir = env::temp_dir();
    log_dir.push("static-analysis-server/logs");
    log_dir
}

#[derive(Debug, Error)]
pub enum CliError {
    #[error("Error parsing arguments: {0:?}")]
    Parsing(#[from] Fail),
    #[error("Invalid port argument {0:?}. It must be a number.")]
    InvalidPort(String),
    #[error("Invalid address argument {0:?}.")]
    InvalidAddress(String),
}

pub enum RocketPreparation {
    ServerInfo {
        rocket: Rocket<Build>,
        state: ServerState,
        tx_shutdown: Sender<Shutdown>,
        guard: Option<Arc<WorkerGuard>>,
    },
    NoServerInteraction,
}

/// Prepares the rocket and sets the configuration and the shared state.
///
/// # Panics
///
/// This function can panic or end the process in case keep-alive is on and graceful exit doesn't work.
/// It should not happen frequently, but it's one of the possibilities.
pub fn prepare_rocket() -> Result<RocketPreparation, CliError> {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();
    let opts = get_opts();

    let matches = opts.parse(&args[1..])?;

    if matches.opt_present("v") {
        println!("Version: {}, revision: {}", CARGO_VERSION, VERSION);
        return Ok(RocketPreparation::NoServerInteraction);
    }

    if matches.opt_present("h") {
        print_usage(&program, &opts);
        return Ok(RocketPreparation::NoServerInteraction);
    }

    // initialize the tracing subscriber here
    // we're only interested in the server logs
    let guard = if matches.opt_present("l") {
        // tracing with logs
        let log_dir = get_log_dir();
        let pid = std::process::id();
        let file_appender = tracing_appender::rolling::daily(log_dir, format!("server.{pid}.log"));
        let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

        // check levels compatibility with from default env
        tracing_subscriber::fmt()
            // .with_env_filter(EnvFilter::from_default_env())
            .with_max_level(tracing::Level::TRACE)
            .json()
            .with_writer(non_blocking)
            .init();
        Some(Arc::new(guard))
    } else {
        // regular tracing subscriber
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .init();
        None
    };

    // server state
    let mut server_state = ServerState::new(matches.opt_str("s"), matches.opt_present("e"));
    let mut rocket_configuration = rocket::config::Config::default();

    // Set up the port in rocket configuration if --port is passed
    if let Some(port_str) = matches.opt_str("p") {
        rocket_configuration.port = match port_str.parse::<u16>() {
            Ok(port) => port,
            Err(_e) => return Err(CliError::InvalidPort(port_str)),
        }
    }

    if matches.opt_present("a") {
        let addr_opt = matches.opt_str("a");
        if let Some(addr) = addr_opt {
            rocket_configuration.address = match addr.parse() {
                Ok(parsed_addr) => parsed_addr,
                Err(_) => return Err(CliError::InvalidAddress(addr)),
            };
        }
    }

    if matches.opt_present("ddsa-runtime") {
        println!("[WARNING] the --ddsa-runtime flag is deprecated and will be removed in the next version");
    }

    // channel used to send the shutdown handler so that we can exit the server gracefully
    let (tx, rx) = channel();

    // if we set up the keepalive mechanism (option -k)
    //   1. Get the timeout value as parameter
    //   2. Start the thread that checks every 5 seconds if we should exit the server
    if matches.opt_present("k") {
        // TODO: (ROB) review this
        // let timeout_sec = match keepalive_timeout.parse::<u128>() {
        //     Ok(sec) => sec,
        //     Err(_) => {
        //         eprintln!("Invalid keep-alive timeout value");
        //         process::exit(1);
        //     }
        // };

        let keepalive_timeout_sec = matches.opt_str("k");

        if let Some(keepalive_timeout) = keepalive_timeout_sec {
            let timeout_sec = keepalive_timeout.parse::<u128>().unwrap();
            let timeout_ms = timeout_sec * 1000;
            server_state.is_keepalive_enabled = true;
            let last_ping_request_timestamp_ms =
                server_state.last_ping_request_timestamp_ms.clone();

            // TODO: (ROB) handle the case where the thread can die/error

            // thread that periodically checks if we should exit the server
            thread::spawn(move || {
                let shutdown_handle: Shutdown = rx.recv().unwrap();
                loop {
                    // get the latest request timestamp and the current one
                    let latest_timestamp = last_ping_request_timestamp_ms
                        .try_read()
                        .map(|x| *x)
                        .unwrap_or_default();
                    let current_timestamp = get_current_timestamp_ms();

                    if latest_timestamp > 0 && current_timestamp > latest_timestamp + timeout_ms {
                        eprintln!("exiting because of timeout, trying to exit gracefully");
                        shutdown_handle.notify();
                        // we give 10 seconds for the process to terminate
                        // if it does not, we abort
                        thread::sleep(Duration::from_secs(10));
                        eprintln!("no graceful exit, aborting the process");
                        process::abort();
                    }
                    thread::sleep(Duration::from_secs(5));
                }
            });
        }
    }

    let state = server_state.clone();
    let rocket = rocket::custom(rocket_configuration).manage(state);

    Ok(RocketPreparation::ServerInfo {
        rocket,
        state: server_state,
        tx_shutdown: tx,
        guard,
    })
}
