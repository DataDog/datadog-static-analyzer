use crate::model::run_configuration::RunConfiguration;
use kernel::config::common::PathConfig;
use secrets::model::secret_rule::SecretRule;

/// Secrets-only settings: the secrets rules to run and its own path selection.
#[derive(Clone)]
pub struct SecretsConfiguration {
    pub ignore_gitignore: bool,
    pub ignore_generated_files: bool,
    pub path_config: PathConfig,
    pub rules: Vec<SecretRule>,
    pub max_file_size_kb: u64,
}

/// Everything a secrets run is configured by: the settings shared across products and secrets'
/// own.
#[derive(Clone, Copy)]
pub struct CliConfigurationSecrets<'a> {
    pub run: &'a RunConfiguration,
    pub secrets: &'a SecretsConfiguration,
}
