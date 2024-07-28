use super::comment_preserver::{prettify_yaml, reconcile_comments};
use super::error::ConfigFileError;
use indexmap::IndexMap;
use kernel::config_file::config_file_to_yaml;
use kernel::{
    config_file::parse_config_file,
    model::config_file::{ConfigFile, PathConfig, PathPattern, RuleConfig, RulesetConfig},
    utils::decode_base64_string,
};
use std::{borrow::Cow, fmt::Debug, ops::Deref};
use tracing::instrument;

#[derive(Debug, Default, Clone, PartialEq)]
pub struct StaticAnalysisConfigFile {
    config_file: ConfigFile,
    original_content: Option<String>,
}

impl From<ConfigFile> for StaticAnalysisConfigFile {
    fn from(value: ConfigFile) -> Self {
        Self {
            config_file: value,
            original_content: None,
        }
    }
}

impl TryFrom<String> for StaticAnalysisConfigFile {
    type Error = ConfigFileError;

    fn try_from(base64_str: String) -> Result<Self, Self::Error> {
        let content = decode_base64_string(base64_str)?;
        if content.trim().is_empty() {
            return Ok(Self::default());
        }
        let config = parse_config_file(&content)?;
        Ok(Self {
            config_file: config,
            original_content: Some(content),
        })
    }
}

impl Deref for StaticAnalysisConfigFile {
    type Target = ConfigFile;
    fn deref(&self) -> &Self::Target {
        &self.config_file
    }
}

fn create_ignored_pattern() -> Vec<PathPattern> {
    vec![PathPattern {
        prefix: "**".into(),
        glob: None,
    }]
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
    /// If successful, this function returns a `Result` containing a `String`. The `String` is the updated content of the static analysis configuration file with the specified rule ignored. If the `config_content_base64` is `None`. A default `StaticAnalysisConfigFile` will be used.
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
    /// let config_content_base64 = kernel::utils::encode_base64_string("...".to_string());
    /// let result = StaticAnalysisConfigFile::with_ignored_rule(rule, config_content_base64);
    /// match result {
    ///     Ok(updated_config) => println!("Updated config: {}", updated_config),
    ///     Err(e) => eprintln!("Error: {}", e),
    /// }
    /// ```
    #[instrument]
    pub fn with_ignored_rule(
        rule: Cow<str>,
        config_content_base64: String,
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

    #[instrument(skip(self))]
    pub fn ignore_rule(&mut self, rule: Cow<str>) {
        let config = &mut self.config_file;
        if let Some((ruleset_name, rule_name)) = rule.split_once('/') {
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
    /// let config_content_base64 = kernel::utils::encode_base64_string("...".to_string());
    /// let result = StaticAnalysisConfigFile::with_added_rulesets(&rulesets, Some(config_content_base64));
    /// match result {
    ///     Ok(updated_config) => println!("Updated config: {}", updated_config),
    ///     Err(e) => eprintln!("Error: {}", e),
    /// }
    /// ```
    #[instrument]
    pub fn with_added_rulesets(
        rulesets: &[impl AsRef<str> + Debug],
        config_content_base64: Option<String>,
    ) -> Result<String, ConfigFileError> {
        let mut original_content: Option<String> = None;

        let mut config = config_content_base64.map_or(Ok(Self::default()), |content| {
            original_content = Some(content.clone());
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
    pub fn add_rulesets(&mut self, rulesets: &[impl AsRef<str> + Debug]) {
        let config = &mut self.config_file;
        for ruleset in rulesets {
            if !config.rulesets.contains_key(ruleset.as_ref()) {
                config
                    .rulesets
                    .insert(ruleset.as_ref().to_owned(), RulesetConfig::default());
            }
        }
    }

    /// Parses the content of a static analysis configuration file and returns the list of rulesets.
    ///
    /// # Parameters
    ///
    /// * `config_content_base64`: The base64-encoded content of the static analysis configuration file.
    ///
    /// # Returns
    ///
    /// This function returns a `Vec<String>`, where each `String` is a ruleset from the configuration file.
    ///
    /// # Example
    ///
    /// ```no_run
    /// let config_content_base64 = kernel::utils::encode_base64_string("...".to_string());
    /// let rulesets = StaticAnalysisConfigFile::to_rulesets(config_content_base64);
    /// for ruleset in rulesets {
    ///     println!("Ruleset: {}", ruleset);
    /// }
    /// ```
    #[instrument]
    pub fn to_rulesets(config_content_base64: String) -> Vec<String> {
        let config = match Self::try_from(config_content_base64) {
            Ok(config) => config,
            Err(e) => {
                tracing::error!(error =?e, "Error trying to parse config file");
                return vec![];
            }
        };
        config.rulesets.iter().map(|rs| rs.0.clone()).collect()
    }

    #[instrument(skip(self))]
    pub fn is_onboarding_allowed(&self) -> bool {
        self.paths.only.is_none() && self.paths.ignore.is_empty()
    }

    /// Serializes the `StaticAnalysisConfigFile` into a YAML string.
    pub fn to_string(&self) -> Result<String, ConfigFileError> {
        let str = config_file_to_yaml(self)?;
        // fix null maps
        let fixed = str.replace(": null", ":");
        // preserve the comments if the original content is provided
        if let Some(original_content) = &self.original_content {
            reconcile_comments(original_content, &fixed, true).map_err(Into::into)
        } else {
            // prettify the content
            prettify_yaml(&fixed).map_err(Into::into)
        }
    }
}

#[cfg(test)]
mod tests {

    use kernel::utils::encode_base64_string;

    fn to_encoded_content(content: &'static str) -> String {
        encode_base64_string(content.to_owned())
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
            let rulesets = StaticAnalysisConfigFile::to_rulesets(content);
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
            let rulesets = StaticAnalysisConfigFile::to_rulesets(content);
            assert_eq!(rulesets, vec!["java-security", "java-1", "ruleset1"]);
        }

        #[test]
        fn it_returns_empty_array_if_bad_format() {
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
            let rulesets = StaticAnalysisConfigFile::to_rulesets(content);
            assert!(rulesets.is_empty());
        }

        #[test]
        fn it_returns_empty_array_if_wrong_version() {
            let content = to_encoded_content(
                r"
schema-version: v354
rulesets:
- java-security
- java-1
",
            );
            let rulesets = StaticAnalysisConfigFile::to_rulesets(content);
            assert!(rulesets.is_empty());
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
            let content = to_encoded_content(
                r"
schema-version: v1
rulesets:
- java-security
- java-1
",
            );
            let config = StaticAnalysisConfigFile::with_added_rulesets(
                &["ruleset1", "ruleset2", "a-ruleset3"],
                Some(content),
            )
            .unwrap();

            let expected = r"
schema-version: v1
rulesets:
  - java-security
  - java-1
  - ruleset1
  - ruleset2
  - a-ruleset3
";

            assert_eq!(config.trim(), expected.trim());
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
            let config = StaticAnalysisConfigFile::with_added_rulesets(
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
            let content = to_encoded_content(
                r"
schema-version: v1
rulesets:
- java-1
- java-security
",
            );
            let config =
                StaticAnalysisConfigFile::with_ignored_rule("ruleset1/rule1".into(), content)
                    .unwrap();

            let expected = r#"
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

            assert_eq!(config.trim(), expected.trim());
        }

        #[test]
        fn it_works_with_a_previously_existing_ruleset() {
            let content = to_encoded_content(
                r"
schema-version: v1
rulesets:
- java-1
- java-security
- ruleset1",
            );
            let config =
                StaticAnalysisConfigFile::with_ignored_rule("ruleset1/rule1".into(), content)
                    .unwrap();

            let expected = r#"
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

            assert_eq!(config.trim(), expected.trim());
        }

        #[test]
        fn it_works_with_a_previously_existing_ruleset_with_same_rule() {
            let content = to_encoded_content(
                r"
schema-version: v1
rulesets:
- java-1
- java-security
- ruleset1:
  rules:
    rule1:
      only:
      - foo/bar
        ",
            );
            let config =
                StaticAnalysisConfigFile::with_ignored_rule("ruleset1/rule1".into(), content)
                    .unwrap();

            let expected = r#"
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

            assert_eq!(config.trim(), expected.trim());
        }

        #[test]
        fn it_works_with_a_previously_existing_ruleset_with_same_rule_with_paths() {
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
            let content = to_encoded_content(
                r"
schema-version: v1
rulesets:
- java-security
- java-1
- ruleset1:
  rules:
    rule2:
      severity: ERROR
",
            );

            let config =
                StaticAnalysisConfigFile::with_ignored_rule("ruleset1/rule1".into(), content)
                    .unwrap();

            let expected = r#"
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

            assert_eq!(config.trim(), expected.trim());
        }

        #[test]
        fn it_keeps_existing_properties_when_ignoring_same_rule() {
            let content = to_encoded_content(
                r"
schema-version: v1
rulesets:
- java-security
- java-1
- ruleset1:
  rules:
    rule2:
      severity: ERROR
",
            );

            let config =
                StaticAnalysisConfigFile::with_ignored_rule("ruleset1/rule2".into(), content)
                    .unwrap();

            let expected = r#"
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

            assert_eq!(config.trim(), expected.trim());
        }
    }

    mod onboarding {

        use super::super::*;
        use super::*;

        #[test]
        fn it_should_return_false_if_only_at_top_level_is_present() {
            let content = to_encoded_content(
                r"
schema-version: v1
rulesets:
    - java-security
    - java-1
only:
    - domains/project1
",
            );

            let config = StaticAnalysisConfigFile::try_from(content).unwrap();
            assert!(!config.is_onboarding_allowed())
        }

        #[test]
        fn it_should_return_false_if_ignore_at_top_level_is_present() {
            let content = to_encoded_content(
                r"
schema-version: v1
rulesets:
    - java-security
    - java-1
ignore:
    - domains/project1
",
            );

            let config = StaticAnalysisConfigFile::try_from(content).unwrap();
            assert!(!config.is_onboarding_allowed())
        }

        #[test]
        fn it_should_return_false_if_ignore_and_only_at_top_level_are_present() {
            let content = to_encoded_content(
                r"
schema-version: v1
rulesets:
    - java-security
    - java-1
only:
    - domains/project1
ignore:
    - domains/project1
",
            );

            let config = StaticAnalysisConfigFile::try_from(content).unwrap();
            assert!(!config.is_onboarding_allowed())
        }

        #[test]
        fn it_should_return_true_if_ignore_and_only_at_top_level_are_not_present() {
            let content = to_encoded_content(
                r"
schema-version: v1
rulesets:
    - java-security
    - java-1
",
            );

            let config = StaticAnalysisConfigFile::try_from(content).unwrap();
            assert!(config.is_onboarding_allowed())
        }

        #[test]
        fn it_should_return_true_with_nested_paths() {
            let content = to_encoded_content(
                r"
schema-version: v1
rulesets:
    - java-security
    - java-1:
      only:
        - domains/project1
",
            );

            let config = StaticAnalysisConfigFile::try_from(content).unwrap();
            assert!(config.is_onboarding_allowed())
        }
    }

    #[test]
    fn try_from_returns_default_config_file_if_empty_string() {
        let expected = super::StaticAnalysisConfigFile::default();
        let config = super::StaticAnalysisConfigFile::try_from(String::new()).unwrap();
        assert_eq!(config, expected);
    }
}
