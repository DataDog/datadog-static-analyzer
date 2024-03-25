use std::time::{SystemTime, UNIX_EPOCH};

/// gets the current timestamp
pub fn get_current_timestamp_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
}

/// gets the kernel version (CARGO)
pub fn get_version() -> String {
    kernel::constants::CARGO_VERSION.to_string()
}

// gets the kernel revision (VERSION)
pub fn get_revision() -> String {
    kernel::constants::VERSION.to_string()
}
