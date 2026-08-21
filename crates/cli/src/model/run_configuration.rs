use common::model::config_method::ConfigMethod;
use kernel::model::common::OutputFormat;

/// Settings that govern how the CLI runs, shared across every product (SAST, secrets) rather
/// than owned by either one.
#[derive(Clone)]
pub struct RunConfiguration {
    pub use_debug: bool,
    pub configuration_method: Option<ConfigMethod>,
    pub source_directory: String,
    pub source_subdirectories: Vec<String>,
    pub output_format: OutputFormat, // SARIF or JSON
    pub output_file: String,
    pub num_cpus: usize, // of cpus to use for parallelism
    pub use_staging: bool,
    pub static_analysis_enabled: bool,
    pub secrets_enabled: bool,
}
