use crate::git_utils::{get_branch, ORIGIN};
use anyhow::anyhow;
use common::model::diff_aware::DiffAware;
use git2::Repository;
use kernel::model::common::OutputFormat;
use kernel::model::config_file::{ConfigMethod, PathConfig};
use kernel::rule_config::RuleConfigProvider;
use sha2::{Digest, Sha256};

use crate::model::datadog_api::DiffAwareRequestArguments;
use crate::utils::get_num_threads_to_use;
use kernel::model::rule::Rule;
use secrets::model::secret_rule::SecretRule;

/// represents the CLI configuration
#[derive(Clone)]
pub struct CliConfiguration {
    pub use_debug: bool,
    pub configuration_method: Option<ConfigMethod>,
    pub ignore_gitignore: bool,
    pub source_directory: String,
    pub source_subdirectories: Vec<String>,
    pub path_config: PathConfig,
    pub rules_file: Option<String>,
    pub output_format: OutputFormat, // SARIF or JSON
    pub output_file: String,
    pub num_cpus: usize, // of cpus to use for parallelism
    pub rules: Vec<Rule>,
    pub rule_config_provider: RuleConfigProvider,
    pub max_file_size_kb: u64,
    pub use_staging: bool,
    pub show_performance_statistics: bool,
    pub ignore_generated_files: bool,
    pub static_analysis_enabled: bool,
    pub secrets_enabled: bool,
    pub secrets_rules: Vec<SecretRule>,
    pub should_verify_checksum: bool,
    pub debug_java_dfa: bool,
}

impl DiffAware for CliConfiguration {
    /// Generate a digest to include in SARIF files to indicate what configuration and rules were used
    /// to run the analysis. To compute the digest, we take the attributes that are important to
    /// run and replicate the analysis such as the ignored paths and rules.
    fn generate_diff_aware_digest(&self) -> String {
        let mut rules_string: Vec<String> = self
            .clone()
            .rules
            .iter()
            .map(|r| r.generate_diff_aware_digest())
            .collect();

        // Important: always make sure the rules string are in the same order so that it does
        // not depend on the order the API returned the rules.
        rules_string.sort();

        let mut secrets_rules_string: Vec<String> = self
            .clone()
            .secrets_rules
            .iter()
            .map(|r| r.generate_diff_aware_digest())
            .collect();

        secrets_rules_string.sort();

        // println!("rules string: {}", rules_string.join("|"));
        let full_config_string = format!(
            "{}:{}:{}:{}::{}:{}:{}:{}",
            self.path_config.ignore.join(","),
            self.path_config
                .only
                .as_ref()
                .map_or("".to_string(), |v| v.join(",")),
            self.ignore_gitignore,
            rules_string.join(","),
            self.max_file_size_kb,
            self.source_subdirectories.join(","),
            self.rule_config_provider.generate_diff_aware_digest(),
            secrets_rules_string.join(",")
        );
        // compute the hash using sha2
        format!("{:x}", Sha256::digest(full_config_string.as_bytes()))
    }
}

impl CliConfiguration {
    pub fn get_num_threads(&self) -> usize {
        get_num_threads_to_use(self.num_cpus)
    }

    /// Generate the diff-aware data from the configuration. It attempts to read
    /// the repository from the directory, get the repository information to get
    /// diff-aware data. If we are not in a repository or cannot get the data
    /// we need, we return an error.
    pub fn generate_diff_aware_request_data(
        &self,
        use_debug: bool,
    ) -> anyhow::Result<DiffAwareRequestArguments> {
        let config_hash = self.generate_diff_aware_digest();

        let repository_opt = Repository::init(&self.source_directory);

        if repository_opt.is_err() {
            eprintln!("Fail to get repository information");
            eprintln!("If the user running the analyzer is different than the user running the analysis, use: git config --global --add safe.directory /path/to/repository");
            eprintln!("In some systems you need to disable the worktreeConfig extension with: git config --unset extensions.worktreeConfig")
        }

        let repository = repository_opt?;

        let repository_url = repository
            .find_remote(ORIGIN)?
            .url()
            .ok_or(anyhow!("cannot get the repository origin URL"))?
            .to_string();

        // let's get the latest commit
        let head = repository.head()?;
        let oid = head.target();
        let branch_option = get_branch(&repository, use_debug);
        match (oid, branch_option) {
            (Some(o), Some(b)) => Ok(DiffAwareRequestArguments {
                repository_url,
                config_hash,
                sha: o.to_string(),
                branch: b,
            }),
            _ => {
                if self.use_debug {
                    println!(
                        "config hash used to attempt to get diff-aware: {}",
                        config_hash
                    )
                }
                Err(anyhow!("cannot get data for diff-aware scanning"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use kernel::model::common::Language;
    use kernel::model::common::OutputFormat::Sarif;
    use kernel::model::rule::{RuleCategory, RuleSeverity, RuleType};

    use super::*;

    #[test]
    fn test_generate_diff_aware_hash() {
        let cli_configuration = CliConfiguration {
            use_debug: true,
            configuration_method: None,
            ignore_gitignore: true,
            source_directory: "bla".to_string(),
            source_subdirectories: vec![],
            path_config: PathConfig::default(),
            rules_file: None,
            output_format: Sarif, // SARIF or JSON
            output_file: "foo".to_string(),
            num_cpus: 2, // of cpus to use for parallelism
            rules: vec![Rule {
                name: "myrule".to_string(),
                short_description_base64: Some("bla".to_string()),
                description_base64: Some("bli".to_string()),
                category: RuleCategory::BestPractices,
                severity: RuleSeverity::Warning,
                language: Language::Python,
                rule_type: RuleType::TreeSitterQuery,
                entity_checked: None,
                code_base64: "mycode".to_string(),
                checksum: "foobar".to_string(),
                pattern: None,
                cwe: None,
                tree_sitter_query_base64: None,
                arguments: vec![],
                tests: vec![],
                is_testing: false,
            }],
            rule_config_provider: RuleConfigProvider::default(),
            max_file_size_kb: 1,
            use_staging: false,
            show_performance_statistics: false,
            ignore_generated_files: false,
            secrets_enabled: false,
            static_analysis_enabled: true,
            secrets_rules: vec![],
            should_verify_checksum: true,
            debug_java_dfa: false,
        };
        assert_eq!(
            cli_configuration.generate_diff_aware_digest(),
            "78fe5ec969b9aa1ea759d6e9bf2acb8a95ddfb5ddb951e6093ed60a88512fd31"
        );
    }

    #[test]
    fn test_generate_diff_aware_secret_rules_order_does_not_matter() {
        let secret_rule1 = SecretRule {
            id: "id1".to_string(),
            name: "name1".to_string(),
            description: "description1".to_string(),
            pattern: "pattern1".to_string(),
            default_included_keywords: vec![],
            validators: Some(vec![]),
            match_validation: None,
        };

        let secret_rule2 = SecretRule {
            id: "id2".to_string(),
            name: "name2".to_string(),
            description: "description2".to_string(),
            pattern: "pattern2".to_string(),
            default_included_keywords: vec![],
            validators: Some(vec![]),
            match_validation: None,
        };

        let cli_configuration_base = CliConfiguration {
            use_debug: true,
            configuration_method: None,
            ignore_gitignore: true,
            source_directory: "bla".to_string(),
            source_subdirectories: vec![],
            path_config: PathConfig::default(),
            rules_file: None,
            output_format: Sarif, // SARIF or JSON
            output_file: "foo".to_string(),
            num_cpus: 2, // of cpus to use for parallelism
            rules: vec![],
            rule_config_provider: Default::default(),
            max_file_size_kb: 1,
            use_staging: false,
            show_performance_statistics: false,
            ignore_generated_files: false,
            secrets_enabled: false,
            static_analysis_enabled: true,
            secrets_rules: vec![],
            should_verify_checksum: true,
            debug_java_dfa: false,
        };

        let mut cli_configuration1 = cli_configuration_base.clone();
        cli_configuration1.secrets_rules = vec![secret_rule1.clone(), secret_rule2.clone()];
        let mut cli_configuration2 = cli_configuration_base.clone();
        cli_configuration2.secrets_rules = vec![secret_rule2.clone(), secret_rule1.clone()];

        assert_eq!(
            cli_configuration1.generate_diff_aware_digest(),
            cli_configuration2.generate_diff_aware_digest(),
        );
    }
}
