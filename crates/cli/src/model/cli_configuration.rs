use anyhow::anyhow;
use git2::Repository;
use sha2::{Digest, Sha256};

use crate::git_utils::get_branch;
use kernel::arguments::ArgumentProvider;
use kernel::model::common::OutputFormat;
use kernel::model::config_file::PathConfig;
use kernel::model::rule::Rule;
use kernel::path_restrictions::PathRestrictions;

use crate::model::datadog_api::DiffAwareRequestArguments;

/// represents the CLI configuration
#[derive(Clone)]
pub struct CliConfiguration {
    pub use_debug: bool,
    pub use_configuration_file: bool,
    pub ignore_gitignore: bool,
    pub source_directory: String,
    pub source_subdirectories: Vec<String>,
    pub path_config: PathConfig,
    pub rules_file: Option<String>,
    pub output_format: OutputFormat, // SARIF or JSON
    pub output_file: String,
    pub num_cpus: usize, // of cpus to use for parallelism
    pub rules: Vec<Rule>,
    pub path_restrictions: PathRestrictions,
    pub argument_provider: ArgumentProvider,
    pub max_file_size_kb: u64,
    pub use_staging: bool,
    pub show_performance_statistics: bool,
    pub scan_for_secrets: bool,
    pub validate_secrets: bool,
    pub secrets_rule_file: Option<std::path::PathBuf>,
    pub ignore_generated_files: bool,
}

impl CliConfiguration {
    /// Generate a digest to include in SARIF files to indicate what configuration and rules were used
    /// to run the analysis. To compute the digest, we take the attributes that are important to
    /// run and replicate the analysis such as the ignored paths and rules.
    pub fn generate_diff_aware_digest(&self) -> String {
        let mut rules_string: Vec<String> = self
            .clone()
            .rules
            .iter()
            .map(|r| r.get_config_hash_string())
            .collect();

        // Important: always make sure the rules string are in the same order so that it does
        // not depend on the order the API returned the rules.
        rules_string.sort();

        // println!("rules string: {}", rules_string.join("|"));
        let full_config_string = format!(
            "{}:{}:{}:{}::{}:{}",
            self.path_config.ignore.join(","),
            self.path_config
                .only
                .as_ref()
                .map_or("".to_string(), |v| v.join(",")),
            self.ignore_gitignore,
            rules_string.join(","),
            self.max_file_size_kb,
            self.source_subdirectories.join(",")
        );
        // compute the hash using sha2
        format!("{:x}", Sha256::digest(full_config_string.as_bytes()))
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
            .find_remote("origin")?
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
            use_configuration_file: true,
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
            path_restrictions: PathRestrictions::default(),
            argument_provider: ArgumentProvider::new(),
            max_file_size_kb: 1,
            use_staging: false,
            show_performance_statistics: false,
            scan_for_secrets: false,
            validate_secrets: false,
            secrets_rule_file: None,
            ignore_generated_files: false,
        };
        assert_eq!(
            cli_configuration.generate_diff_aware_digest(),
            "aadc07afa2ab7afb253e52a9be80bf7a756f953ce1f6de80f8717f0fa9584360"
        );
    }
}
