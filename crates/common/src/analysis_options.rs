use serde::{Deserialize, Serialize};
use std::time::Duration;

// Used internally to pass options to the analysis
#[derive(Clone, Deserialize, Debug, Serialize)]
pub struct AnalysisOptions {
    pub log_output: bool,
    pub use_debug: bool,
    pub ignore_generated_files: bool,
    pub rule_timeout: Option<Duration>,
}

impl Default for AnalysisOptions {
    fn default() -> Self {
        Self {
            log_output: false,
            use_debug: false,
            ignore_generated_files: true,
            rule_timeout: None,
        }
    }
}
