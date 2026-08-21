use crate::git_utils::{get_branch, ORIGIN};
use crate::model::datadog_api::DiffAwareRequestArguments;
use crate::model::run_configuration::RunConfiguration;
use anyhow::anyhow;
use common::model::diff_aware::DiffAware;
use git2::Repository;
use kernel::config::common::PathConfig;
use kernel::model::rule::Rule;
use kernel::rule_config::RuleConfigProvider;
use sha2::{Digest, Sha256};

/// SAST-only settings: everything needed to select files for and run static analysis.
#[derive(Clone)]
pub struct SastConfiguration {
    pub ignore_gitignore: bool,
    pub path_config: PathConfig,
    pub rules_file: Option<String>,
    pub rules: Vec<Rule>,
    pub rule_config_provider: RuleConfigProvider,
    pub max_file_size_kb: u64,
    pub show_performance_statistics: bool,
    pub ignore_generated_files: bool,
    pub should_verify_checksum: bool,
    pub debug_java_dfa: bool,
}

/// Everything a static analysis run is configured by: the settings shared across products and
/// SAST's own.
#[derive(Clone, Copy)]
pub struct CliConfigurationSast<'a> {
    pub run: &'a RunConfiguration,
    pub sast: &'a SastConfiguration,
}

impl DiffAware for CliConfigurationSast<'_> {
    /// Generate a digest to include in SARIF files to indicate what configuration and rules were
    /// used to run the analysis. To compute the digest, we take the attributes that are important
    /// to run and replicate the analysis such as the ignored paths and rules.
    fn generate_diff_aware_digest(&self) -> String {
        let mut rules_string: Vec<String> = self
            .sast
            .rules
            .iter()
            .map(|r| r.generate_diff_aware_digest())
            .collect();

        // Important: always make sure the rules string are in the same order so that it does
        // not depend on the order the API returned the rules.
        rules_string.sort();

        let full_config_string = format!(
            "{}:{}:{}:{}:{}:{}:{}",
            self.sast.path_config.ignore.join(","),
            self.sast
                .path_config
                .only
                .as_ref()
                .map_or("".to_string(), |v| v.join(",")),
            self.sast.ignore_gitignore,
            rules_string.join(","),
            self.sast.max_file_size_kb,
            self.sast.rule_config_provider.generate_diff_aware_digest(),
            self.run.source_subdirectories.join(","),
        );
        // compute the hash using sha2
        format!("{:x}", Sha256::digest(full_config_string.as_bytes()))
    }
}

impl CliConfigurationSast<'_> {
    /// Generate the diff-aware data from the run and SAST configuration. It attempts to read
    /// the repository from the directory, get the repository information to get
    /// diff-aware data. If we are not in a repository or cannot get the data
    /// we need, we return an error.
    pub fn generate_diff_aware_request_data(
        &self,
        use_debug: bool,
    ) -> anyhow::Result<DiffAwareRequestArguments> {
        let config_hash = self.generate_diff_aware_digest();

        let repository_opt = Repository::open(&self.run.source_directory);

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
                if self.run.use_debug {
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
    use super::*;
    use kernel::model::common::{Language, OutputFormat};
    use kernel::model::rule::{Rule, RuleCategory, RuleSeverity, RuleType};
    use kernel::rule_config::RuleConfigProvider;

    fn run_configuration(source_subdirectories: Vec<String>) -> RunConfiguration {
        RunConfiguration {
            use_debug: false,
            configuration_method: None,
            source_directory: "/tmp".to_string(),
            source_subdirectories,
            output_format: OutputFormat::Sarif,
            output_file: String::new(),
            num_cpus: 2,
            use_staging: false,
            static_analysis_enabled: true,
            secrets_enabled: false,
        }
    }

    fn sast_configuration() -> SastConfiguration {
        SastConfiguration {
            ignore_gitignore: true,
            path_config: PathConfig::default(),
            rules_file: None,
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
                documentation_url: None,
            }],
            rule_config_provider: RuleConfigProvider::default(),
            max_file_size_kb: 1,
            show_performance_statistics: false,
            ignore_generated_files: false,
            should_verify_checksum: true,
            debug_java_dfa: false,
        }
    }

    #[test]
    fn test_generate_diff_aware_hash() {
        let run = run_configuration(vec![]);
        let sast = sast_configuration();
        let cli_config = CliConfigurationSast {
            run: &run,
            sast: &sast,
        };
        assert_eq!(
            cli_config.generate_diff_aware_digest(),
            "97b004b7ed3fb2d7b0fcd80120897efe36d84cb2b7aacfcfa5d069e71918e9a7"
        );
    }

    /// Changing the analyzed subdirectory scope must invalidate a cached diff-aware result.
    #[test]
    fn diff_aware_hash_depends_on_source_subdirectories() {
        let sast = sast_configuration();
        let run_root = run_configuration(vec![]);
        let run_subdir = run_configuration(vec!["src".to_string()]);

        let digest_root = CliConfigurationSast {
            run: &run_root,
            sast: &sast,
        }
        .generate_diff_aware_digest();
        let digest_subdir = CliConfigurationSast {
            run: &run_subdir,
            sast: &sast,
        }
        .generate_diff_aware_digest();

        assert_ne!(digest_root, digest_subdir);
    }
}
