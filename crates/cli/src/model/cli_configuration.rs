use kernel::model::common::OutputFormat;
use kernel::model::rule::Rule;
use std::collections::HashMap;

// Vectors of references to the "only" and "ignore" paths in the configuration file.
#[derive(Clone, Debug)]
pub struct PathConfigStack {
    // Subsequent levels of "only", setting new restrictions each.
    pub only: Vec<Vec<String>>,
    // A vector of "ignore"
    pub ignore: Vec<String>,
}

// A rule with the "only" and "ignore" paths that apply to it.
#[derive(Clone)]
pub struct RuleWithPaths {
    pub rule: Rule,
    pub paths: PathConfigStack,
}

/// represents the CLI configuratoin
#[derive(Clone)]
pub struct CliConfiguration {
    pub use_debug: bool,
    pub use_configuration_file: bool,
    pub ignore_gitignore: bool,
    pub source_directory: String,
    pub source_subdirectories: Vec<String>,
    pub ignore_paths: Vec<String>,
    pub only_paths: Option<Vec<String>>,
    pub rules_file: Option<String>,
    pub output_format: OutputFormat, // SARIF or JSON
    pub output_file: String,
    pub num_cpus: usize, // of cpus to use for parallelism
    pub rules: Vec<Rule>,
    pub rule_restrictions: HashMap<String, PathConfigStack>,
    pub max_file_size_kb: u64,
    pub use_staging: bool,
}
