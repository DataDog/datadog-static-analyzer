use getopts::Options;
use kernel::constants::{CARGO_VERSION, VERSION};
use rocket::{Build, Rocket, Shutdown};
use std::sync::mpsc::{channel, Sender};
use std::time::Duration;
use std::{env, process, thread};

use super::state::ServerState;
use super::utils::get_current_timestamp_ms;

fn print_usage(program: &str, opts: Options) {
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
    opts
}

/// Prepares the rocket and sets the configuration and the shared state.
///
/// # Panics
///
/// This function can panic or end the process in case the configuration is not correct.
pub fn prepare_rocket() -> (Rocket<Build>, ServerState, Sender<Shutdown>) {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();
    let opts = get_opts();

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => {
            eprintln!("error when parsing arguments: {}", f);
            process::exit(22); // invalid argument code
        }
    };

    if matches.opt_present("v") {
        println!("Version: {}, revision: {}", CARGO_VERSION, VERSION);
        process::exit(0);
    }

    if matches.opt_present("h") {
        print_usage(&program, opts);
        process::exit(0);
    }

    // server state
    let mut server_state = ServerState::new(matches.opt_str("s"), matches.opt_present("e"));
    let mut rocket_configuration = rocket::config::Config::default();

    // Set up the port in rocket configuration if --port is passed
    if matches.opt_present("p") {
        let port_opt = matches.opt_str("p");
        if let Some(port_str) = port_opt {
            let port_res = port_str.parse::<u16>();
            if port_res.is_err() {
                eprintln!("Invalid port argument");
                process::exit(1)
            }
            rocket_configuration.port = port_res.unwrap();
        }
    }

    if matches.opt_present("a") {
        let addr_opt = matches.opt_str("a");
        if let Some(addr) = addr_opt {
            rocket_configuration.address = addr.parse().expect("should be able to parse addr");
        }
    }

    // channel used to send the shutdown handler so that we can exit the server gracefully
    let (tx, rx) = channel();

    // if we set up the keepalive mechanism (option -k)
    //   1. Get the timeout value as parameter
    //   2. Start the thread that checks every 5 seconds if we should exit the server
    if matches.opt_present("k") {
        let keepalive_timeout_sec = matches.opt_str("k");

        if let Some(keepalive_timeout) = keepalive_timeout_sec {
            let timeout_sec = keepalive_timeout.parse::<u128>().unwrap();
            let timeout_ms = timeout_sec * 1000;
            server_state.is_keepalive_enabled = true;
            let last_ping_request_timestamp_ms =
                server_state.last_ping_request_timestamp_ms.clone();

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
                        shutdown_handle.clone().notify();
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

    (rocket, server_state, tx)
}
