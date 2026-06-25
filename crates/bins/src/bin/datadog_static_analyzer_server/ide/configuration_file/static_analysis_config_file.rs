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

/// Whether the IDE-active config file uses the legacy (`static-analysis.datadog.*`) or
/// unified (`code-security.datadog.*`) format. Determined by filename, never content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigFormat {
    Legacy,
    Unified,
}

impl<'a> From<Option<&'a str>> for ConfigFormat {
    /// Maps the IDE-supplied `schema_version` string to a [`ConfigFormat`].
    /// `"v1"` is the canonical wire value for [`ConfigFormat::Unified`].
    /// Absent or unrecognized values default to [`ConfigFormat::Legacy`] for backward
    /// compatibility with older extensions that never sent this field.
    fn from(schema_version: Option<&'a str>) -> Self {
        match schema_version {
            Some("v1") => Self::Unified,
            _ => Self::Legacy,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct StaticAnalysisConfigFile {
    config_file: WithVersion<file_legacy::ConfigFile, file_v1::YamlConfigFile>,
    original_content: Option<String>,
}

impl Default for StaticAnalysisConfigFile {
    fn default() -> Self {
        Self {
            config_file: WithVersion::CodeSecurity(Default::default()),
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

/// Bundles content with an optional format hint for [`TryFrom`] parsing.
///
/// `None` means no format was declared by the caller (e.g. deprecated routes); blank content
/// will fall back to [`StaticAnalysisConfigFile::default_legacy`] in that case.
#[derive(Debug)]
pub struct WithHint<T>(pub T, pub Option<ConfigFormat>);

impl TryFrom<WithHint<String>> for StaticAnalysisConfigFile {
    type Error = ConfigFileError;

    fn try_from(WithHint(content, hint): WithHint<String>) -> Result<Self, Self::Error> {
        Self::from_yaml_content(content, hint)
    }
}

impl TryFrom<WithHint<Base64String>> for StaticAnalysisConfigFile {
    type Error = ConfigFileError;

    fn try_from(WithHint(base64_str, hint): WithHint<Base64String>) -> Result<Self, Self::Error> {
        let decoded = decode_base64_string(base64_str.0)?;
        Self::from_yaml_content(decoded, hint)
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
    /// Parses a raw YAML configuration string (not base64-encoded) into a [`StaticAnalysisConfigFile`].
    ///
    /// When `content` is blank, `hint` determines the empty default: [`ConfigFormat::Unified`]
    /// produces a unified empty file; anything else (including `None`) produces the legacy default.
    fn from_yaml_content(
        content: String,
        hint: Option<ConfigFormat>,
    ) -> Result<Self, ConfigFileError> {
        use serde::de::Error;
        if content.trim().is_empty() {
            return Ok(match hint {
                Some(ConfigFormat::Legacy) | None => Self::default_legacy(),
                _ => Self::default(),
            });
        }
        let parsed = parse_any_schema_yaml(&content).map_err(|err| match err {
            // Artificially represent this as a "parse" error for backwards compatibility.
            ConfigError::UnsupportedSchema(_) => ConfigFileError::Parser {
                source: serde_yaml::Error::custom(err),
            },
            ConfigError::Parse(err) => ConfigFileError::Parser { source: err },
        })?;
        let config_file = match parsed {
            WithVersion::Legacy(yaml) => WithVersion::Legacy(file_legacy::ConfigFile::from(yaml)),
            WithVersion::CodeSecurity(yaml) => WithVersion::CodeSecurity(yaml),
        };
        Ok(Self {
            config_file,
            original_content: Some(content),
        })
    }

    /// Ignores a specific rule in the static analysis configuration file.
    ///
    /// # Parameters
    ///
    /// * `rule`: The fully-qualified rule name (`<ruleset>/<rule>`) to ignore.
    /// * `config_content_base64`: The base64-encoded content of the static analysis configuration file.
    /// * `declared_format`: The format the caller claims the file is in, derived from the
    ///   filename or the `schema_version` field of the request.
    ///
    /// # Returns
    ///
    /// If successful, returns a `String` containing the updated YAML of the configuration file
    /// with the specified rule ignored.
    ///
    /// # Errors
    ///
    /// Returns a `ConfigFileError` if:
    ///
    /// * The `config_content_base64` string cannot be base64-decoded.
    /// * The decoded content cannot be parsed as a static analysis configuration file.
    /// * The detected format of the parsed content does not match `declared_format`.
    ///
    /// # Example
    ///
    /// ```no_run
    /// let rule = "ruleset/rule-to-ignore".into();
    /// let config_content_base64 = Base64String(kernel::utils::encode_base64_string("...".to_string()));
    /// let result = StaticAnalysisConfigFile::with_ignored_rule(rule, config_content_base64, ConfigFormat::Legacy);
    /// match result {
    ///     Ok(updated_config) => println!("Updated config: {}", updated_config),
    ///     Err(e) => eprintln!("Error: {}", e),
    /// }
    /// ```
    #[instrument]
    pub fn with_ignored_rule(
        rule: Cow<str>,
        config_content_base64: Base64String,
        declared_format: ConfigFormat,
    ) -> Result<String, ConfigFileError> {
        let mut config = Self::try_from(WithHint(config_content_base64, Some(declared_format)))
            .map_err(|e| {
                tracing::error!(error =?e, "Error trying to parse config file");
                e
            })?;
        config.validate_format(declared_format)?;
        config.ignore_rule(rule);
        config.to_string().map_err(|e| {
            tracing::error!(error =?e, "Error trying to serialize config file");
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
    /// When `config_content_base64` is `None`, a new file is created in the format implied by
    /// `declared_format` ([`ConfigFormat::Unified`] → unified schema, [`ConfigFormat::Legacy`] →
    /// legacy schema). Duplicate rulesets are silently ignored.
    ///
    /// # Parameters
    ///
    /// * `rulesets`: A slice of strings, where each string is a ruleset to be added.
    /// * `config_content_base64`: The base64-encoded content of the static analysis configuration
    ///   file, or `None` to start from an empty file.
    /// * `declared_format`: The format the caller claims the file is in, derived from the
    ///   filename or the `schema_version` field of the request.
    ///
    /// # Returns
    ///
    /// If successful, returns a `String` containing the updated YAML of the configuration file
    /// with the new rulesets added.
    ///
    /// # Errors
    ///
    /// Returns a `ConfigFileError` if:
    ///
    /// * The `config_content_base64` string cannot be base64-decoded.
    /// * The decoded content cannot be parsed as a static analysis configuration file.
    /// * The detected format of the parsed content does not match `declared_format`.
    ///
    /// # Example
    ///
    /// ```no_run
    /// let rulesets = vec!["ruleset-to-add".to_string()];
    /// let config_content_base64 = Base64String(kernel::utils::encode_base64_string("...".to_string()));
    /// let result = StaticAnalysisConfigFile::with_added_rulesets(&rulesets, Some(config_content_base64), ConfigFormat::Legacy);
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
        declared_format: ConfigFormat,
    ) -> Result<String, ConfigFileError> {
        let mut config = match config_content_base64 {
            Some(content) => {
                let config =
                    Self::try_from(WithHint(content, Some(declared_format))).map_err(|e| {
                        tracing::error!(error = ?e, "Error trying to parse config file");
                        e
                    })?;
                config.validate_format(declared_format)?;
                config
            }
            None => match declared_format {
                ConfigFormat::Unified => Self::default(),
                ConfigFormat::Legacy => Self::default_legacy(),
            },
        };
        config.add_rulesets(rulesets);
        config.to_string().map_err(|e| {
            tracing::error!(error = ?e, "Error trying to serialize config file");
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

    /// Returns the config format as detected from the parsed content.
    fn detected_format(&self) -> ConfigFormat {
        match &self.config_file {
            WithVersion::Legacy(_) => ConfigFormat::Legacy,
            WithVersion::CodeSecurity(_) => ConfigFormat::Unified,
        }
    }

    /// Returns `Err(SchemaMismatch)` when the detected format does not match `declared`.
    pub fn validate_format(&self, declared: ConfigFormat) -> Result<(), ConfigFileError> {
        if self.detected_format() == declared {
            Ok(())
        } else {
            Err(ConfigFileError::SchemaMismatch)
        }
    }

    /// Returns an empty legacy-format config, used as the fallback when the caller
    /// has declared [`ConfigFormat::Legacy`] or provided no format hint at all.
    fn default_legacy() -> Self {
        Self {
            config_file: WithVersion::Legacy(Default::default()),
            original_content: None,
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
    use crate::datadog_static_analyzer_server::ide::configuration_file::static_analysis_config_file::{Base64String, WithHint};

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
            let config = StaticAnalysisConfigFile::try_from(WithHint(content, None)).unwrap();
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
            let config = StaticAnalysisConfigFile::try_from(WithHint(content, None)).unwrap();
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
            let err = StaticAnalysisConfigFile::try_from(WithHint(content, None)).unwrap_err();
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
            let err = StaticAnalysisConfigFile::try_from(WithHint(content, None)).unwrap_err();
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
                ConfigFormat::Legacy,
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
                ConfigFormat::Legacy,
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
                ConfigFormat::Legacy,
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
                ConfigFormat::Legacy,
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
                ConfigFormat::Legacy,
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
                ConfigFormat::Legacy,
            )
            .unwrap_err();

            assert_eq!(err.code(), 1);
        }

        #[test]
        fn it_creates_new_unified_file_when_no_existing_content() {
            let config = StaticAnalysisConfigFile::with_added_rulesets(
                &["ruleset1", "ruleset2"],
                None,
                ConfigFormat::Unified,
            )
            .unwrap();

            assert!(config.contains("schema-version: v1.0"), "body: {config}");
            assert!(config.contains("ruleset1"), "body: {config}");
            assert!(config.contains("ruleset2"), "body: {config}");
        }

        #[test]
        fn it_works_simple_unified() {
            // language=yaml
            let unified = r"
schema-version: v1.0
sast:
  use-rulesets:
    - python-security
";
            let config = StaticAnalysisConfigFile::with_added_rulesets(
                &["java-security"],
                Some(to_encoded_content(unified)),
                ConfigFormat::Unified,
            )
            .unwrap();

            assert!(config.contains("schema-version: v1.0"), "body: {config}");
            assert!(config.contains("python-security"), "body: {config}");
            assert!(config.contains("java-security"), "body: {config}");
        }

        #[test]
        fn it_fails_if_schema_mismatch_legacy_declared_as_unified() {
            // language=yaml
            let legacy = to_encoded_content(
                r"
schema-version: v1
rulesets:
- java-security
",
            );
            let err = StaticAnalysisConfigFile::with_added_rulesets(
                &["ruleset1"],
                Some(legacy),
                ConfigFormat::Unified,
            )
            .unwrap_err();

            assert_eq!(err.code(), 4);
        }

        #[test]
        fn it_fails_if_schema_mismatch_unified_declared_as_legacy() {
            // language=yaml
            let unified = to_encoded_content(
                r"
schema-version: v1.0
sast:
  use-rulesets:
    - java-security
",
            );
            let err = StaticAnalysisConfigFile::with_added_rulesets(
                &["ruleset1"],
                Some(unified),
                ConfigFormat::Legacy,
            )
            .unwrap_err();

            assert_eq!(err.code(), 4);
        }

        #[test]
        fn empty_content_with_unified_format_creates_unified_default() {
            let config = StaticAnalysisConfigFile::with_added_rulesets(
                &["ruleset1", "ruleset2"],
                Some(to_encoded_content("\n")),
                ConfigFormat::Unified,
            )
            .unwrap();

            assert!(config.contains("schema-version: v1.0"), "body: {config}");
            assert!(config.contains("ruleset1"), "body: {config}");
            assert!(config.contains("ruleset2"), "body: {config}");
        }

        #[test]
        fn empty_content_with_legacy_format_creates_legacy_default() {
            let config = StaticAnalysisConfigFile::with_added_rulesets(
                &["ruleset1", "ruleset2"],
                Some(to_encoded_content("\n")),
                ConfigFormat::Legacy,
            )
            .unwrap();

            assert!(!config.contains("schema-version: v1.0"), "body: {config}");
            assert!(config.contains("ruleset1"), "body: {config}");
            assert!(config.contains("ruleset2"), "body: {config}");
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
                ConfigFormat::Legacy,
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
                ConfigFormat::Legacy,
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
                ConfigFormat::Legacy,
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
            let config = StaticAnalysisConfigFile::with_ignored_rule(
                "ruleset1/rule1".into(),
                content,
                ConfigFormat::Legacy,
            )
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
            let err = StaticAnalysisConfigFile::with_ignored_rule(
                "ruleset1/rule1".into(),
                content,
                ConfigFormat::Legacy,
            )
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
                ConfigFormat::Legacy,
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
                ConfigFormat::Legacy,
            )
            .unwrap();

            assert_eq!(config.trim(), legacy_expected.trim());
        }

        #[test]
        fn it_works_with_unified_content() {
            // language=yaml
            let unified = r"
schema-version: v1.0
sast:
  use-rulesets:
    - ruleset1
";
            let config = StaticAnalysisConfigFile::with_ignored_rule(
                "ruleset1/rule1".into(),
                to_encoded_content(unified),
                ConfigFormat::Unified,
            )
            .unwrap();

            assert!(config.contains("schema-version: v1.0"), "body: {config}");
            assert!(config.contains("ruleset1"), "body: {config}");
            assert!(config.contains("rule1"), "body: {config}");
        }

        #[test]
        fn it_fails_if_schema_mismatch_legacy_declared_as_unified() {
            // language=yaml
            let legacy = to_encoded_content(
                r"
schema-version: v1
rulesets:
- java-security
",
            );
            let err = StaticAnalysisConfigFile::with_ignored_rule(
                "java-security/rule1".into(),
                legacy,
                ConfigFormat::Unified,
            )
            .unwrap_err();

            assert_eq!(err.code(), 4);
        }

        #[test]
        fn it_fails_if_schema_mismatch_unified_declared_as_legacy() {
            // language=yaml
            let unified = to_encoded_content(
                r"
schema-version: v1.0
sast:
  use-rulesets:
    - java-security
",
            );
            let err = StaticAnalysisConfigFile::with_ignored_rule(
                "java-security/rule1".into(),
                unified,
                ConfigFormat::Legacy,
            )
            .unwrap_err();

            assert_eq!(err.code(), 4);
        }

        #[test]
        fn empty_content_with_unified_format_ignores_rule() {
            let config = StaticAnalysisConfigFile::with_ignored_rule(
                "ruleset1/rule1".into(),
                to_encoded_content("\n"),
                ConfigFormat::Unified,
            )
            .unwrap();

            assert!(config.contains("schema-version: v1.0"), "body: {config}");
            assert!(config.contains("ruleset1"), "body: {config}");
            assert!(config.contains("rule1"), "body: {config}");
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
                let config =
                    StaticAnalysisConfigFile::try_from(WithHint(to_encoded_content(yaml), None))
                        .unwrap();
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
                let config =
                    StaticAnalysisConfigFile::try_from(WithHint(to_encoded_content(yaml), None))
                        .unwrap();
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
                let config =
                    StaticAnalysisConfigFile::try_from(WithHint(to_encoded_content(yaml), None))
                        .unwrap();
                assert!(config.is_onboarding_allowed())
            }
        }
    }

    #[test]
    fn default_is_unified() {
        let config = super::StaticAnalysisConfigFile::default();
        assert_eq!(config.detected_format(), super::ConfigFormat::Unified);
    }

    #[test]
    fn try_from_empty_string_with_no_hint_returns_legacy() {
        let config =
            super::StaticAnalysisConfigFile::try_from(WithHint(String::new(), None)).unwrap();
        assert_eq!(config.detected_format(), super::ConfigFormat::Legacy);
    }

    #[test]
    fn try_from_empty_string_with_legacy_hint_returns_legacy() {
        let config = super::StaticAnalysisConfigFile::try_from(WithHint(
            String::new(),
            Some(super::ConfigFormat::Legacy),
        ))
        .unwrap();
        assert_eq!(config.detected_format(), super::ConfigFormat::Legacy);
    }

    #[test]
    fn try_from_empty_string_with_unified_hint_returns_unified() {
        let config = super::StaticAnalysisConfigFile::try_from(WithHint(
            String::new(),
            Some(super::ConfigFormat::Unified),
        ))
        .unwrap();
        assert_eq!(config.detected_format(), super::ConfigFormat::Unified);
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
            super::ConfigFormat::Legacy,
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
