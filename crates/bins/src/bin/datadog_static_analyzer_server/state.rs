use super::utils::get_current_timestamp_ms;
use std::sync::{Arc, RwLock};

#[derive(Clone)]
pub struct ServerState {
    pub last_ping_request_timestamp_ms: Arc<RwLock<u128>>,
    pub static_directory: Option<String>,
    pub is_shutdown_enabled: bool,
    pub is_keepalive_enabled: bool,
}

impl ServerState {
    pub fn new(static_directory: Option<String>, is_shutdown_enabled: bool) -> Self {
        Self {
            last_ping_request_timestamp_ms: Arc::new(RwLock::new(get_current_timestamp_ms())),
            static_directory,
            is_shutdown_enabled,
            is_keepalive_enabled: false,
        }
    }
}
