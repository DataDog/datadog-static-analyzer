use kernel::model::common::OutputFormat;
use kernel::model::rule::Rule;

/// represents the CLI configuratoin
#[derive(Clone)]
pub struct CliConfiguration {
    pub use_debug: bool,
    pub use_configuration_file: bool,
    pub ignore_gitignore: bool,
    pub source_directory: String,
    pub source_subdirectory: Option<String>,
    pub ignore_paths: Vec<String>,
    pub rules_file: Option<String>,
    pub output_format: OutputFormat, // SARIF or JSON
    pub output_file: String,
    pub num_cpus: usize, // of cpus to use for parallelism
    pub rules: Vec<Rule>,
    pub max_file_size_kb: u64,
    pub use_staging: bool,
}
