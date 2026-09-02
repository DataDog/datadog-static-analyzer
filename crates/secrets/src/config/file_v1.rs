// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026 Datadog, Inc.

use crate::config::common::YamlSchemaVersion;
use common::model::path_config::{PathConfig, PathPattern};
use serde::{Deserialize, Serialize, Serializer};

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("unsupported schema `{0}`")]
    WrongSchema(YamlSchemaVersion),
    #[error(transparent)]
    Parse(#[from] serde_yaml::Error),
}

/// Code Security v1.x configuration file.
/// Use [`parse_yaml`] to construct one.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct YamlConfigFile {
    pub(crate) schema_version: YamlSchemaVersion,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secrets: Option<YamlSecretsConfig>,
    // Unparsed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) sast: Option<serde_yaml::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) iac: Option<serde_yaml::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) sca: Option<serde_yaml::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) iast: Option<serde_yaml::Value>,
}

impl Default for YamlConfigFile {
    fn default() -> Self {
        Self {
            schema_version: YamlSchemaVersion::MajorMinor((1, 5)),
            sast: None,
            secrets: None,
            iac: None,
            sca: None,
            iast: None,
        }
    }
}

impl<'de> Deserialize<'de> for YamlConfigFile {
    fn deserialize<D>(_deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Err(serde::de::Error::custom("Use file_v1::parse_yaml()"))
    }
}

impl YamlConfigFile {
    /// Extracts and unwraps the secrets configuration
    ///
    /// # Panics
    /// Panics if the underlying isn't a [`YamlSecretsConfigMinor6`].
    #[cfg(test)]
    pub fn secrets6(&self) -> &YamlSecretsConfigMinor6 {
        self.secrets
            .as_ref()
            .and_then(|s| match s {
                YamlSecretsConfig::Minor6(secrets) => Some(secrets),
                #[allow(unreachable_patterns)]
                _ => None,
            })
            .unwrap()
    }
}

/// Code Security v1.x Configuration
#[derive(Debug, Clone, PartialEq)]
pub struct ConfigFile {
    secrets: Option<SecretsConfig>,
}

impl ConfigFile {
    pub fn secrets(&self) -> Option<&SecretsConfig> {
        self.secrets.as_ref()
    }
}

impl From<YamlConfigFile> for ConfigFile {
    fn from(value: YamlConfigFile) -> Self {
        Self {
            secrets: value.secrets.map(Into::into),
        }
    }
}

/// No Secrets section prior to v1.5 so this dummy struct purposely will fail to deserialize if a
/// "secrets" section with any content is given anyway.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct YamlSecretsConfigMinor0 {}

/// Secrets configuration for v1.5+ (until schema changes)
/// This represents the Secrets schema. When Secrets adds/changes fields in a future
/// minor version, a new YamlSecretsConfigMinorN struct should be created.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub struct YamlSecretsConfigMinor6 {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) global_config: Option<YamlSecretsGlobalConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) experimental_ast_filter: Option<bool>,
}

/// Secrets configuration for v1.5
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub struct YamlSecretsConfigMinor5 {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) global_config: Option<YamlSecretsGlobalConfig>,
}

/// All the different schemas that the "secrets" property in the v1.x configuration file can take.
#[derive(Debug, Clone, PartialEq)]
pub enum YamlSecretsConfig {
    Minor5(YamlSecretsConfigMinor5),
    /// Secrets schema used from v1.6+
    Minor6(YamlSecretsConfigMinor6),
}

impl Default for YamlSecretsConfig {
    fn default() -> Self {
        // This should always be the latest minor version implemented
        Self::Minor6(Default::default())
    }
}

impl YamlSecretsConfig {
    /// Returns a reference to the `global-config`.
    pub fn global_config(&self) -> Option<&YamlSecretsGlobalConfig> {
        match self {
            YamlSecretsConfig::Minor6(cfg) => cfg.global_config.as_ref(),
            YamlSecretsConfig::Minor5(cfg) => cfg.global_config.as_ref(),
        }
    }

    /// Returns the `experimental-ast-filter` flag.
    pub fn experimental_ast_filter(&self) -> Option<bool> {
        match self {
            YamlSecretsConfig::Minor6(cfg) => cfg.experimental_ast_filter,
            YamlSecretsConfig::Minor5(cfg) => None,
        }
    }
}

impl<'de> Deserialize<'de> for YamlSecretsConfig {
    fn deserialize<D>(_deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Err(serde::de::Error::custom("Use file_v1::parse_yaml()"))
    }
}

impl Serialize for YamlSecretsConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            YamlSecretsConfig::Minor5(config) => config.serialize(serializer),
            YamlSecretsConfig::Minor6(config) => config.serialize(serializer),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SecretsConfig {
    pub global_config: Option<SecretsGlobalConfig>,
    pub experimental_ast_filter: bool,
}

impl From<YamlSecretsConfig> for SecretsConfig {
    fn from(value: YamlSecretsConfig) -> Self {
        match value {
            YamlSecretsConfig::Minor5(cfg) => SecretsConfig {
                global_config: cfg.global_config.map(Into::into),
                experimental_ast_filter: false,
            },
            YamlSecretsConfig::Minor6(cfg) => SecretsConfig {
                global_config: cfg.global_config.map(Into::into),
                experimental_ast_filter: cfg.experimental_ast_filter.unwrap_or(false),
            },
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Default, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub struct YamlSecretsGlobalConfig {
    #[serde(flatten)]
    pub path_config: YamlPathConfig,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) use_gitignore: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) ignore_generated_files: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) max_file_size_kb: Option<u64>,
}

#[derive(Debug, PartialEq, Clone)]
pub struct SecretsGlobalConfig {
    pub paths: Option<PathConfig>,
    pub use_gitignore: Option<bool>,
    pub max_file_size_kb: Option<u64>,
    pub ignore_generated_files: Option<bool>,
}

impl From<YamlSecretsGlobalConfig> for SecretsGlobalConfig {
    fn from(value: YamlSecretsGlobalConfig) -> Self {
        Self {
            paths: value.path_config.into(),
            use_gitignore: value.use_gitignore,
            max_file_size_kb: value.max_file_size_kb,
            ignore_generated_files: value.ignore_generated_files,
        }
    }
}

/// A combination of `only-paths` and `ignore-paths` fields, intended to be inlined via [`serde(flatten)`].
#[derive(Debug, Clone, Deserialize, Serialize, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub struct YamlPathConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub only_paths: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ignore_paths: Option<Vec<String>>,
}

impl From<YamlPathConfig> for Option<PathConfig> {
    fn from(value: YamlPathConfig) -> Self {
        (value != YamlPathConfig::default()).then(|| PathConfig {
            only: value
                .only_paths
                .map(|only| only.into_iter().map(PathPattern::from).collect()),
            ignore: value
                .ignore_paths
                .unwrap_or_default()
                .into_iter()
                .map(PathPattern::from)
                .collect(),
        })
    }
}

impl From<Option<PathConfig>> for YamlPathConfig {
    fn from(value: Option<PathConfig>) -> Self {
        match value {
            Some(path_config) => Self {
                only_paths: path_config
                    .only
                    .map(|only| only.into_iter().map(String::from).collect()),
                ignore_paths: if path_config.ignore.is_empty() {
                    None
                } else {
                    Some(path_config.ignore.into_iter().map(String::from).collect())
                },
            },
            None => YamlPathConfig::default(),
        }
    }
}

/// Parses a Code Security v1.x configuration file
pub fn parse_yaml(config_contents: &str) -> Result<YamlConfigFile, ParseError> {
    /// The specification for Code Security v1.x (which will never change)
    #[derive(Deserialize)]
    #[serde(rename_all = "kebab-case")]
    #[serde(deny_unknown_fields)]
    struct Major1 {
        schema_version: YamlSchemaVersion,
        #[serde(default)]
        sast: Option<serde_yaml::Value>,
        #[serde(default)]
        secrets: Option<serde_yaml::Value>,
        #[serde(default)]
        iac: Option<serde_yaml::Value>,
        #[serde(default)]
        sca: Option<serde_yaml::Value>,
        #[serde(default)]
        iast: Option<serde_yaml::Value>,
    }

    let base: Major1 = serde_yaml::from_str(config_contents)?;

    match base.schema_version {
        YamlSchemaVersion::MajorMinor((1, minor)) => {
            let mut secrets: Option<YamlSecretsConfig> = None;
            match minor {
                // The `secrets` section was introduced in v1.5, so earlier v1.x schemas should
                // have nothing to read. Deserializing into `YamlSecretsConfigMinor0` will always
                // fails when a non-empty "secrets" section is present to disallow it.
                ..5 => {
                    if let Some(value) = base.secrets {
                        let _: YamlSecretsConfigMinor0 =
                            serde_yaml::from_value(value).map_err(ParseError::Parse)?;
                    }
                }
                5.. => {
                    if let Some(value) = base.secrets {
                        let config: YamlSecretsConfigMinor6 =
                            serde_yaml::from_value(value).map_err(ParseError::Parse)?;
                        let _ = secrets.insert(YamlSecretsConfig::Minor6(config));
                    }
                }
            }

            Ok(YamlConfigFile {
                schema_version: base.schema_version,
                sast: base.sast,
                secrets,
                iac: base.iac,
                sca: base.sca,
                iast: base.iast,
            })
        }
        _ => Err(ParseError::WrongSchema(base.schema_version)),
    }
}

/// Tests for the general Code Security v1.x parser.
#[cfg(test)]
mod cs_tests {
    use crate::config::common::YamlSchemaVersion;
    use crate::config::file_v1::{parse_yaml, ParseError, YamlConfigFile};

    #[test]
    fn parse_optional_fields() {
        // language=yaml
        let config = r"
schema-version: v1.0
";
        let res = parse_yaml(config).unwrap();
        assert_eq!(
            res,
            YamlConfigFile {
                schema_version: YamlSchemaVersion::MajorMinor((1, 0)),
                sast: None,
                secrets: None,
                iac: None,
                sca: None,
                iast: None,
            }
        );
    }

    #[test]
    fn parse_no_schema_version() {
        // language=yaml
        let config = r"
";
        let err = parse_yaml(config).unwrap_err();
        assert!(
            matches!(err, ParseError::Parse(e) if e.to_string().contains("missing field `schema-version`"))
        );
    }

    /// No validation of the properties outside of sast.
    #[test]
    fn parse_no_validation() {
        // language=yaml
        let config = r"
schema-version: v1.0
sast: [123]
# secrets:
iac: 1.23
sca:
  one: true
iast: null
";
        let res = parse_yaml(config).expect("should pass validation");
        assert!(res.sast.is_some());
        assert!(res.secrets.is_none());
        assert!(res.iac.is_some());
        assert!(res.sca.is_some());
        assert!(res.iast.is_none());
    }

    #[test]
    fn parse_deny_unknown() {
        // language=yaml
        let config = r"
schema-version: v1.0
surely-this-is-not-in-the-schema: ...right?
";
        let err = parse_yaml(config).unwrap_err();
        let err_msg = "unknown field `surely-this-is-not-in-the-schema`";
        assert!(matches!(err, ParseError::Parse(e) if e.to_string().contains(err_msg)));
    }

    #[test]
    fn parse_config_only_major1() {
        let err = parse_yaml("schema-version: v1\n").unwrap_err();
        assert!(
            matches!(err, ParseError::WrongSchema(v) if v == YamlSchemaVersion::Invalid("v1".to_string()))
        );

        // Unsupported major version
        let err = parse_yaml("schema-version: v9.0\n").unwrap_err();
        assert!(matches!(
            err,
            ParseError::WrongSchema(YamlSchemaVersion::MajorMinor((9, 0)))
        ));

        // v1.x
        assert!(parse_yaml("schema-version: v1.0\n").is_ok());
        // (Some arbitrarily large minor version number that we'll never reach...hopefully)
        assert!(parse_yaml("schema-version: v1.222\n").is_ok());
    }

    /// The `secrets` section only exists from v1.5. Providing one on an earlier v1.x schema is an
    /// error rather than being silently accepted and dropped.
    #[test]
    fn secrets_section_rejected_before_minor5() {
        for version in ["v1.0", "v1.4"] {
            let config = format!(
                "schema-version: {version}\nsecrets:\n  global-config:\n    only-paths:\n      - src\n"
            );
            let err = parse_yaml(&config).expect_err("`secrets` should be rejected before v1.5");
            assert!(matches!(err, ParseError::Parse(_)), "{version}: {err}");
        }

        // The same section is accepted from v1.5 on.
        assert!(parse_yaml(
            "schema-version: v1.5\nsecrets:\n  global-config:\n    only-paths:\n      - src\n"
        )
        .is_ok());

        // A schema before v1.5 with no `secrets` key at all stays valid.
        assert!(parse_yaml("schema-version: v1.0\n").is_ok());
    }
}

/// Tests specific 'secrets' property within the Code Security v1.x file.
#[cfg(test)]
mod secrets_tests {
    use crate::config::file_v1::{
        parse_yaml, ConfigFile, ParseError, SecretsConfig, SecretsGlobalConfig,
    };
    use common::model::path_config::{PathConfig, PathPattern};

    /// All fields in v1.6 Secrets config
    #[test]
    fn parse_fields() {
        let config = r#"
schema-version: v1.6
secrets:
  global-config:
    only-paths:
      - src
    ignore-paths:
      - test_*
      - fixture_*
    use-gitignore: false
    max-file-size-kb: 2000
    ignore-generated-files: true
  experimental-ast-filter: true
"#;
        let cfg = ConfigFile::from(parse_yaml(config).unwrap());

        assert_eq!(
            cfg.secrets.unwrap(),
            SecretsConfig {
                global_config: Some(SecretsGlobalConfig {
                    paths: Some(PathConfig {
                        only: Some(vec![PathPattern::from("src".to_string())]),
                        ignore: vec![
                            PathPattern::from("test_*".to_string()),
                            PathPattern::from("fixture_*".to_string()),
                        ],
                    }),
                    use_gitignore: Some(false),
                    max_file_size_kb: Some(2000),
                    ignore_generated_files: Some(true),
                }),
                experimental_ast_filter: true,
            }
        )
    }

    /// All fields in v1.6 Secrets config
    #[test]
    fn parse_fields_no_global_config() {
        let config = r#"
schema-version: v1.6
secrets:
  experimental-ast-filter: true
"#;
        let cfg = ConfigFile::from(parse_yaml(config).unwrap());

        assert_eq!(
            cfg.secrets.unwrap(),
            SecretsConfig {
                global_config: None,
                experimental_ast_filter: true,
            }
        )
    }

    /// `experimental-ast-filter` defaults to `false` when absent.
    #[test]
    fn parse_experimental_ast_filter_defaults_to_false() {
        let config = r"
schema-version: v1.5
secrets:
  global-config:
    only-paths:
      - src
";
        let cfg = ConfigFile::from(parse_yaml(config).unwrap());
        assert!(!cfg.secrets.unwrap().experimental_ast_filter);
    }

    /// All relevant Yaml* structs fail if an unknown field is present.
    #[test]
    fn parse_deny_unknown() {
        let unknown_field = "surely-this-is-not-in-the-schema: ...right?";
        let err_msg = "unknown field `surely-this-is-not-in-the-schema`";

        // YamlSecretsConfig
        let yaml_secrets_config = format!(
            "\
schema-version: v1.5
secrets:
  {unknown_field}
        "
        );
        // YamlSecretsGlobalConfig
        let yaml_secrets_global_config = format!(
            "\
schema-version: v1.5
secrets:
  global-config:
    {unknown_field}
        "
        );

        for config in &[yaml_secrets_config, yaml_secrets_global_config] {
            let err = parse_yaml(config).unwrap_err();
            assert!(matches!(err, ParseError::Parse(e) if e.to_string().contains(err_msg)));
        }
    }
}
