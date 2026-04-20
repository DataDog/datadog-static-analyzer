use super::comment_preserver::{prettify_yaml, reconcile_comments};
use super::error::ConfigFileError;
use indexmap::IndexMap;
use itertools::Itertools;
use kernel::config::common::{
    parse_any_schema_yaml, ConfigError, PathConfig, PathPattern, RuleConfig, RulesetConfig,
    WithVersion,
};
use kernel::config::file_legacy::config_file_to_yaml;
use kernel::config::{file_legacy, file_v1};
use kernel::utils::decode_base64_string;
use std::{borrow::Cow, fmt::Debug};
use tracing::instrument;

const WILDCARD_IGNORE: &str = "**";

#[derive(Debug, Clone, PartialEq)]
pub struct StaticAnalysisConfigFile {
    config_file: WithVersion<file_legacy::ConfigFile, file_v1::YamlConfigFile>,
    original_content: Option<String>,
}

impl Default for StaticAnalysisConfigFile {
    fn default() -> Self {
        Self {
            config_file: WithVersion::Legacy(Default::default()),
            original_content: None,
        }
    }
}

impl From<file_legacy::ConfigFile> for StaticAnalysisConfigFile {
    fn from(value: file_legacy::ConfigFile) -> Self {
        Self {
            config_file: WithVersion::Legacy(value),
            original_content: None,
        }
    }
}

/// Soft deprecated, used for when older routes still pass Base64 encoded configuration file
///
#[derive(Debug)]
pub struct Base64String(pub String);

impl TryFrom<Base64String> for StaticAnalysisConfigFile {
    type Error = ConfigFileError;

    fn try_from(base64_str: Base64String) -> Result<Self, Self::Error> {
        let decoded = decode_base64_string(base64_str.0)?;
        StaticAnalysisConfigFile::try_from(decoded)
    }
}

impl TryFrom<String> for StaticAnalysisConfigFile {
    type Error = ConfigFileError;

    fn try_from(content: String) -> Result<Self, Self::Error> {
        Self::from_yaml_content(content)
    }
}

impl StaticAnalysisConfigFile {
    /// Parses a raw YAML configuration string (not base64-encoded) into a [`StaticAnalysisConfigFile`].
    fn from_yaml_content(content: String) -> Result<Self, ConfigFileError> {
        use serde::de::Error;
        if content.trim().is_empty() {
            return Ok(Self::default());
        }
        let parsed = if cfg!(test) {
            parse_any_schema_yaml(&content).map_err(|err| {
                match err {
                    // Artificially represent this as a "parse" error for backwards compatibility.
                    ConfigError::UnsupportedSchema(_) => ConfigFileError::Parser {
                        source: serde_yaml::Error::custom(err),
                    },
                    ConfigError::Parse(err) => ConfigFileError::Parser { source: err },
                }
            })
        } else {
            file_legacy::parse_yaml(&content)
                .map(WithVersion::Legacy)
                .map_err(|err| ConfigFileError::Parser { source: err })
        }?;
        let config_file = match parsed {
            WithVersion::Legacy(yaml) => WithVersion::Legacy(file_legacy::ConfigFile::from(yaml)),
            WithVersion::CodeSecurity(yaml) => WithVersion::CodeSecurity(yaml),
        };
        Ok(Self {
            config_file,
            original_content: Some(content),
        })
    }
}

/// Returns a vec representing an ignored path (via the `**` glob).
fn create_ignored_path() -> Vec<String> {
    vec![WILDCARD_IGNORE.to_string()]
}

fn create_ignored_pattern() -> Vec<PathPattern> {
    create_ignored_path()
        .into_iter()
        .map(|path_str| PathPattern {
            prefix: std::path::PathBuf::from(path_str),
            glob: None,
        })
        .collect()
}

fn create_ignored_rule() -> RuleConfig {
    RuleConfig {
        paths: PathConfig {
            ignore: create_ignored_pattern(),
            only: None,
        },
        ..Default::default()
    }
}

impl StaticAnalysisConfigFile {
    /// Ignores a specific rule in the static analysis configuration file.
    ///
    /// # Parameters
    ///
    /// * `rule`: The rule to be ignored.
    /// * `config_content_base64`: The base64-encoded content of the static analysis configuration file.
    ///
    /// # Returns
    ///
    /// If successful, this function returns a `Result` containing a `String`. The `String` is the updated content of the static analysis configuration file with the specified rule ignored.
    ///
    /// # Errors
    ///
    /// This function will return an error of type `ConfigFileError` if:
    ///
    /// * The `config_content_base64` string cannot be base64-decoded.
    /// * The decoded content cannot be parsed as a static analysis configuration file.
    ///
    /// # Example
    ///
    /// ```no_run
    /// let rule = "RULE_TO_IGNORE".into();
    /// let config_content_base64 = Base64String(kernel::utils::encode_base64_string("...".to_string()));
    /// let result = StaticAnalysisConfigFile::with_ignored_rule(rule, config_content_base64);
    /// match result {
    ///     Ok(updated_config) => println!("Updated config: {}", updated_config),
    ///     Err(e) => eprintln!("Error: {}", e),
    /// }
    /// ```
    #[instrument]
    pub fn with_ignored_rule(
        rule: Cow<str>,
        config_content_base64: Base64String,
    ) -> Result<String, ConfigFileError> {
        let mut config = Self::try_from(config_content_base64).map_err(|e| {
            tracing::error!(error =?e, "Error trying to parse config file");
            e
        })?;

        config.ignore_rule(rule);
        config.to_string().map_err(|e| {
            tracing::error!(error =?e, "Error trying to serializing config file");
            e
        })
    }

    /// Ignores a specific rule in the static analysis configuration file.
    ///
    /// # Parameters
    ///
    /// * `rule`: The rule to be ignored.
    ///
    #[instrument(skip(self))]
    pub fn ignore_rule(&mut self, rule: Cow<str>) {
        let Some((ruleset_name, rule_name)) = rule.split_once('/') else {
            return;
        };
        match &mut self.config_file {
            WithVersion::Legacy(config) => {
                // the ruleset may exist and contain other rules so we
                // can't update it blindly
                if let Some(existing_ruleset) = config.rulesets.get_mut(ruleset_name) {
                    // if the rule already exists we need to see if the rule was already present.
                    // if that's the case, we need to keep the old properties
                    if let Some(existing_rule) = existing_ruleset.rules.get_mut(rule_name) {
                        existing_rule.paths.ignore = create_ignored_pattern();
                    } else {
                        existing_ruleset
                            .rules
                            .insert(rule_name.to_string(), create_ignored_rule());
                    }
                } else {
                    // we can add the new ruleset
                    let mut rules_to_ignore = IndexMap::new();
                    rules_to_ignore.insert(rule_name.to_string(), create_ignored_rule());

                    config.rulesets.insert(
                        ruleset_name.to_string(),
                        RulesetConfig {
                            rules: rules_to_ignore,
                            ..Default::default()
                        },
                    );
                }
            }
            WithVersion::CodeSecurity(config) => {
                let sast = config.sast.get_or_insert_default();
                let _ = sast.add_rule_ignore(rule);
            }
        }
    }

    /// Adds new rulesets to the static analysis configuration file.
    ///
    /// # Parameters
    ///
    /// * `rulesets`: A slice of strings, where each string is a ruleset to be added.
    /// * `config_content_base64`: The base64-encoded content of the static analysis configuration file. This is optional.
    ///
    /// # Returns
    ///
    /// If successful, this function returns a `Result` containing a `String`. The `String` is the updated content of the static analysis configuration file with the new rulesets added.
    ///
    /// # Errors
    ///
    /// This function will return an error of type `ConfigFileError` if:
    ///
    /// * The `config_content_base64` string cannot be base64-decoded.
    /// * The decoded content cannot be parsed as a static analysis configuration file.
    ///
    /// # Example
    ///
    /// ```no_run
    /// let rulesets = vec!["RULESET_TO_ADD".to_string()];
    /// let config_content_base64 = Base64String(kernel::utils::encode_base64_string("...".to_string()));
    /// let result = StaticAnalysisConfigFile::with_added_rulesets(&rulesets, Some(config_content_base64));
    /// match result {
    ///     Ok(updated_config) => println!("Updated config: {}", updated_config),
    ///     Err(e) => eprintln!("Error: {}", e),
    /// }
    /// ```
    #[instrument]
    #[allow(deprecated)]
    pub fn with_added_rulesets(
        rulesets: &[impl AsRef<str> + Debug],
        config_content_base64: Option<Base64String>,
    ) -> Result<String, ConfigFileError> {
        let mut config = config_content_base64.map_or(Ok(Self::default()), |content| {
            Self::try_from(content).map_err(|e| {
                tracing::error!(error =?e, "Error trying to parse config file");
                e
            })
        })?;

        config.add_rulesets(rulesets);
        config.to_string().map_err(|e| {
            tracing::error!(error =?e, "Error trying to serializing config file");
            e
        })
    }

    #[instrument(skip(self))]
    #[deprecated(note = "IDEs stopped adding new rule sets, remove when endpoint is removed")]
    pub fn add_rulesets(&mut self, rulesets: &[impl AsRef<str> + Debug]) {
        match &mut self.config_file {
            WithVersion::Legacy(config) => {
                for ruleset in rulesets {
                    if !config.rulesets.contains_key(ruleset.as_ref()) {
                        config
                            .rulesets
                            .insert(ruleset.as_ref().to_owned(), RulesetConfig::default());
                    }
                }
            }
            WithVersion::CodeSecurity(config) => {
                config.sast.get_or_insert_default().add_rulesets(rulesets);
            }
        }
    }

    /// Extracts the list of SAST rulesets from this configuration.
    #[instrument(skip(self))]
    pub fn sast_rulesets(&self) -> Vec<String> {
        match &self.config_file {
            WithVersion::Legacy(config) => config.rulesets.iter().map(|rs| rs.0.clone()).collect(),
            WithVersion::CodeSecurity(config) => config
                .sast
                .as_ref()
                .and_then(|s| s.use_rulesets().map(|s| s.to_owned()))
                .unwrap_or_default(),
        }
    }

    #[instrument(skip(self))]
    pub fn is_onboarding_allowed(&self) -> bool {
        match &self.config_file {
            WithVersion::Legacy(config) => {
                config.paths.only.is_none() && config.paths.ignore.is_empty()
            }
            WithVersion::CodeSecurity(config) => {
                let Some(sast) = &config.sast else {
                    return true;
                };
                sast.global_config().is_none()
                    || sast.global_config().as_ref().is_some_and(|c| {
                        c.path_config.ignore_paths.is_none() && c.path_config.only_paths.is_none()
                    })
            }
        }
    }

    /// Serializes the `StaticAnalysisConfigFile` into a YAML string.
    ///
    /// # Returns
    ///
    /// This function will try to prettify/format the yaml and preserve the existing comments.
    /// If it fails to do so, it will return a raw yaml with the default format and without comments.
    ///
    /// # Errors
    ///
    /// Returns a `ConfigFileError` if something goes wrong.
    #[instrument(skip(self))]
    pub fn to_string(&self) -> Result<String, ConfigFileError> {
        let yaml = match &self.config_file {
            WithVersion::Legacy(config) => {
                let str = config_file_to_yaml(config)?;
                // fix null maps, note that str will not have comments and it will be using the default serde format.
                str.lines()
                    .map(|l| {
                        if l.ends_with(": null") {
                            l.replace(": null", ":")
                        } else {
                            l.to_string()
                        }
                    })
                    .join("\n")
            }
            WithVersion::CodeSecurity(config) => serde_yaml::to_string(&config)?,
        };
        // reconcile and format
        // NOTE: if this fails, we're going to return the content
        // and swallow the error.
        self.original_content
            .as_ref()
            .map_or_else(
                || prettify_yaml(&yaml),
                |original_content| reconcile_comments(original_content, &yaml, true),
            )
            .or_else(|e| {
                tracing::debug!(error = ?e, "Reconciliation or formatting error: {}", e.to_string());
                Ok::<String, ConfigFileError>(yaml)
            })
    }
}

#[cfg(test)]
mod tests {

    use kernel::utils::encode_base64_string;
    use crate::datadog_static_analyzer_server::ide::configuration_file::static_analysis_config_file::Base64String;

    fn to_encoded_content(content: &'static str) -> Base64String {
        Base64String(encode_base64_string(content.to_owned()))
    }

    mod get_rulesets {
        use super::super::*;
        use super::*;

        #[test]
        fn it_works_simple() {
            let content = to_encoded_content(
                r"
schema-version: v1
rulesets:
- java-security
- java-1
",
            );
            let config = StaticAnalysisConfigFile::try_from(content).unwrap();
            let rulesets = config.sast_rulesets();
            assert_eq!(rulesets, vec!["java-security", "java-1"]);
        }

        #[test]
        fn it_works_complex() {
            let content = to_encoded_content(
                r#"
schema-version: v1
rulesets:
  - java-security
  - java-1
  - ruleset1:
    rules:
      rule2:
        only:
          - foo/bar
      rule1:
        ignore:
          - "**"
"#,
            );
            let config = StaticAnalysisConfigFile::try_from(content).unwrap();
            let rulesets = config.sast_rulesets();
            assert_eq!(rulesets, vec!["java-security", "java-1", "ruleset1"]);
        }

        #[test]
        fn it_returns_error_if_bad_format() {
            let content = to_encoded_content(
                r"
schema-version: v1
rulesets:
- java-security
- java-1
- ruleset1:
        rules:
            rule2:
                only:
                - foo/bar
            rule1:
                ignore:
                - '**'
",
            );
            let err = StaticAnalysisConfigFile::try_from(content).unwrap_err();
            assert_eq!(err.code(), 1);
        }

        #[test]
        fn it_returns_error_if_wrong_version() {
            let content = to_encoded_content(
                r"
schema-version: v354
rulesets:
- java-security
- java-1
",
            );
            let err = StaticAnalysisConfigFile::try_from(content).unwrap_err();
            assert_eq!(err.code(), 1);
        }
    }

    mod add_rulesets {
        use super::super::*;
        use super::*;

        #[test]
        fn it_works_without_content() {
            let config = StaticAnalysisConfigFile::with_added_rulesets(
                &["ruleset1", "ruleset2", "a-ruleset3"],
                None,
            )
            .unwrap();
            let expected = r"
schema-version: v1
rulesets:
  - ruleset1
  - ruleset2
  - a-ruleset3
";
            assert_eq!(config.trim(), expected.trim());
        }

        #[test]
        fn it_works_empty_content() {
            let config = StaticAnalysisConfigFile::with_added_rulesets(
                &["ruleset1"],
                Some(to_encoded_content("\n")),
            )
            .unwrap();
            let expected = r"
schema-version: v1
rulesets:
  - ruleset1
";
            assert_eq!(config.trim(), expected.trim());
        }

        #[test]
        fn it_works_simple() {
            // language=yaml
            let legacy = r"
schema-version: v1
rulesets:
- java-security
- java-1
";
            // language=yaml
            let legacy_expected = r"
schema-version: v1
rulesets:
  - java-security
  - java-1
  - ruleset1
  - ruleset2
  - a-ruleset3
";

            let config = StaticAnalysisConfigFile::with_added_rulesets(
                &["ruleset1", "ruleset2", "a-ruleset3"],
                Some(to_encoded_content(legacy)),
            )
            .unwrap();

            assert_eq!(config.trim(), legacy_expected.trim());
        }

        #[test]
        fn add_no_duplicate_rulesets() {
            // language=yaml
            let legacy = r"
schema-version: v1
rulesets:
- java-security
";
            // language=yaml
            let legacy_expected = r"
schema-version: v1
rulesets:
  - java-security
  - new-ruleset
";

            let config = StaticAnalysisConfigFile::with_added_rulesets(
                &["new-ruleset", "new-ruleset"],
                Some(to_encoded_content(legacy)),
            )
            .unwrap();

            assert_eq!(config.trim(), legacy_expected.trim());
        }

        #[test]
        fn it_works_complex() {
            // language=yaml
            let content = to_encoded_content(
                r#"
schema-version: v1
rulesets:
  - java-security
  - java-1
  - ruleset1:
    rules:
      rule2:
        only:
          - foo/bar
      rule1:
        ignore:
          - "**"
"#,
            );
            let config = StaticAnalysisConfigFile::with_added_rulesets(
                &["ruleset1", "ruleset2", "a-ruleset3"],
                Some(content),
            )
            .unwrap();

            // language=yaml
            let expected = r#"
schema-version: v1
rulesets:
  - java-security
  - java-1
  - ruleset1:
    rules:
      rule2:
        only:
          - foo/bar
      rule1:
        ignore:
          - "**"
  - ruleset2
  - a-ruleset3
"#;

            assert_eq!(config.trim(), expected.trim());
        }

        #[test]
        fn it_fails_if_wrong_version() {
            // language=yaml
            let content = to_encoded_content(
                r"
schema-version: v354
rulesets:
- java-security
- java-1
",
            );
            let err = StaticAnalysisConfigFile::with_added_rulesets(
                &["ruleset1", "ruleset2", "a-ruleset3"],
                Some(content),
            )
            .unwrap_err();

            assert_eq!(err.code(), 1);
        }
    }

    mod ignore_rules {
        use super::super::*;
        use super::*;

        #[test]
        fn it_works_with_non_previously_existing_ruleset() {
            // language=yaml
            let legacy = r"
schema-version: v1
rulesets:
- java-1
- java-security
";
            // language=yaml
            let legacy_expected = r#"
schema-version: v1
rulesets:
  - java-1
  - java-security
  - ruleset1:
    rules:
      rule1:
        ignore:
          - "**"
"#;

            let config = StaticAnalysisConfigFile::with_ignored_rule(
                "ruleset1/rule1".into(),
                to_encoded_content(legacy),
            )
            .unwrap();

            assert_eq!(config.trim(), legacy_expected.trim());
        }

        #[test]
        fn it_works_with_a_previously_existing_ruleset() {
            // language=yaml
            let legacy = r"
schema-version: v1
rulesets:
- java-1
- java-security
- ruleset1
";
            // language=yaml
            let legacy_expected = r#"
schema-version: v1
rulesets:
  - java-1
  - java-security
  - ruleset1:
    rules:
      rule1:
        ignore:
          - "**"
"#;

            let config = StaticAnalysisConfigFile::with_ignored_rule(
                "ruleset1/rule1".into(),
                to_encoded_content(legacy),
            )
            .unwrap();

            assert_eq!(config.trim(), legacy_expected.trim());
        }

        /// NOTE: While conceptually redundant with [`it_keeps_existing_properties_when_ignoring_same_rule`],
        /// this is explicitly tested because [`PathConfig`] is a single struct with `only` and `ignore`,
        /// and so `ignore` should be the only field mutated.
        #[test]
        fn it_works_with_a_previously_existing_ruleset_with_same_rule_path_config() {
            // language=yaml
            let legacy = r"
schema-version: v1
rulesets:
- java-1
- java-security
- ruleset1:
  rules:
    rule1:
      only:
      - foo/bar
";
            // language=yaml
            let legacy_expected = r#"
schema-version: v1
rulesets:
  - java-1
  - java-security
  - ruleset1:
    rules:
      rule1:
        only:
          - foo/bar
        ignore:
          - "**"
"#;

            let config = StaticAnalysisConfigFile::with_ignored_rule(
                "ruleset1/rule1".into(),
                to_encoded_content(legacy),
            )
            .unwrap();

            assert_eq!(config.trim(), legacy_expected.trim());
        }

        #[test]
        fn it_works_with_a_previously_existing_ruleset_with_same_rule_with_paths() {
            // language=yaml
            let content = to_encoded_content(
                r"
schema-version: v1
rulesets:
- java-1
- java-security
- ruleset1:
  rules:
    rule2:
      only:
      - foo/bar
",
            );
            let config =
                StaticAnalysisConfigFile::with_ignored_rule("ruleset1/rule1".into(), content)
                    .unwrap();

            // language=yaml
            let expected = r#"
schema-version: v1
rulesets:
  - java-1
  - java-security
  - ruleset1:
    rules:
      rule2:
        only:
          - foo/bar
      rule1:
        ignore:
          - "**"
"#;
            assert_eq!(config.trim(), expected.trim());
        }

        #[test]
        fn it_fails_if_wrong_version() {
            // language=yaml
            let content = to_encoded_content(
                r"
schema-version: v354
rulesets:
- java-security
- java-1
",
            );
            let err = StaticAnalysisConfigFile::with_ignored_rule("ruleset1/rule1".into(), content)
                .unwrap_err();

            assert_eq!(err.code(), 1);
        }

        #[test]
        fn it_keeps_existing_properties_when_ignoring_other_rules() {
            // language=yaml
            let legacy = r"
schema-version: v1
rulesets:
- java-security
- java-1
- ruleset1:
  rules:
    rule2:
      severity: ERROR
";
            // language=yaml
            let legacy_expected = r#"
schema-version: v1
rulesets:
  - java-security
  - java-1
  - ruleset1:
    rules:
      rule2:
        severity: ERROR
      rule1:
        ignore:
          - "**"
"#;

            let config = StaticAnalysisConfigFile::with_ignored_rule(
                "ruleset1/rule1".into(),
                to_encoded_content(legacy),
            )
            .unwrap();

            assert_eq!(config.trim(), legacy_expected.trim());
        }

        #[test]
        fn it_keeps_existing_properties_when_ignoring_same_rule() {
            // language=yaml
            let legacy = r"
schema-version: v1
rulesets:
- java-security
- java-1
- ruleset1:
  rules:
    rule2:
      severity: ERROR
";
            // language=yaml
            let legacy_expected = r#"
schema-version: v1
rulesets:
  - java-security
  - java-1
  - ruleset1:
    rules:
      rule2:
        ignore:
          - "**"
        severity: ERROR
"#;

            let config = StaticAnalysisConfigFile::with_ignored_rule(
                "ruleset1/rule2".into(),
                to_encoded_content(legacy),
            )
            .unwrap();

            assert_eq!(config.trim(), legacy_expected.trim());
        }
    }

    mod onboarding {

        use super::super::*;
        use super::*;

        #[test]
        fn it_should_return_false_for_top_level_ignore_only() {
            // language=yaml
            let legacy_only = r"#
schema-version: v1
rulesets:
    - java-security
    - java-1
only:
    - domains/project1
";
            // language=yaml
            let legacy_ignore = r"
schema-version: v1
rulesets:
    - java-security
    - java-1
ignore:
    - domains/project1
";
            // language=yaml
            let legacy_both = r"
schema-version: v1
rulesets:
    - java-security
    - java-1
only:
    - domains/project1
ignore:
    - domains/project1
";
            // language=yaml
            let v1_only = r"
schema-version: v1.0
sast:
  global-config:
    only-paths:
      - domains/project1
";
            // language=yaml
            let v1_ignore = r"
schema-version: v1.0
sast:
  global-config:
    ignore-paths:
      - domains/project1/abc
";
            // language=yaml
            let v1_both = r"
schema-version: v1.0
sast:
  global-config:
    only-paths:
      - domains/project1
    ignore-paths:
      - domains/project1/abc
";

            for yaml in [
                legacy_only,
                legacy_ignore,
                legacy_both,
                v1_only,
                v1_ignore,
                v1_both,
            ] {
                let config = StaticAnalysisConfigFile::try_from(to_encoded_content(yaml)).unwrap();
                assert!(!config.is_onboarding_allowed())
            }
        }

        #[test]
        fn it_should_return_true_if_ignore_and_only_at_top_level_are_not_present() {
            // language=yaml
            let legacy = r"
schema-version: v1
rulesets:
    - java-security
    - java-1
";
            // language=yaml
            let v1_no_sast = r"
schema-version: v1.0
";
            // language=yaml
            let v1_with_sast_global = r"
schema-version: v1.0
sast:
  global-config:
    # A global config that doesn't specify only-paths/ignore-paths
    use-gitignore: true
";

            for yaml in [legacy, v1_no_sast, v1_with_sast_global] {
                let config = StaticAnalysisConfigFile::try_from(to_encoded_content(yaml)).unwrap();
                assert!(config.is_onboarding_allowed())
            }
        }

        #[test]
        fn it_should_return_true_with_nested_paths() {
            // language=yaml
            let legacy = r"
schema-version: v1
rulesets:
    - java-security
    - java-1:
      only:
        - domains/project1
";
            // language=yaml
            let v1 = r"
schema-version: v1.0
sast:
  ruleset-configs:
    java-1:
      only-paths:
        - domains/project1
";

            for yaml in [legacy, v1] {
                let config = StaticAnalysisConfigFile::try_from(to_encoded_content(yaml)).unwrap();
                assert!(config.is_onboarding_allowed())
            }
        }
    }

    #[test]
    fn try_from_returns_default_config_file_if_empty_string() {
        let expected = super::StaticAnalysisConfigFile::default();
        let config = super::StaticAnalysisConfigFile::try_from(String::new()).unwrap();
        assert_eq!(config, expected);
    }

    #[test]
    fn it_removes_null_on_maps_only() {
        let content = to_encoded_content(
            r#"
schema-version: v1
rulesets:
- java-security
- java-1
- ruleset1:
  rules:
    rule2:
      only:
        - "foo/bar: null"
"#,
        );
        let config = super::StaticAnalysisConfigFile::with_added_rulesets(
            &["ruleset1", "ruleset2", "a-ruleset3"],
            Some(content),
        )
        .unwrap();

        let expected = r#"
schema-version: v1
rulesets:
  - java-security
  - java-1
  - ruleset1:
    rules:
      rule2:
        only:
          - "foo/bar: null"
  - ruleset2
  - a-ruleset3
"#;

        assert_eq!(config.trim(), expected.trim());
    }
}
