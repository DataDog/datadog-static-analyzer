// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026 Datadog, Inc.

use crate::config::common::{
    PathConfig, PathPattern, RuleConfig, RulesetConfig, YamlSchemaVersion,
};
use crate::config::file_legacy;
use crate::config::file_legacy::{AnyAsString, UniqueKeyMap};
use crate::model::rule::RuleSeverity;
use indexmap::IndexMap;
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
    pub(crate) sast: Option<YamlSastConfig>,
    // Unparsed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) secrets: Option<serde_yaml::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) iac: Option<serde_yaml::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) sca: Option<serde_yaml::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) iast: Option<serde_yaml::Value>,
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
    /// Extracts and unwraps the sast configuration
    ///
    /// # Panics
    /// Panics if the underlying isn't a [`YamlSastConfigMinor0`].
    #[cfg(test)]
    pub fn sast0(&self) -> &YamlSastConfigMinor0 {
        self.sast
            .as_ref()
            .and_then(|s| match s {
                YamlSastConfig::Minor0(sast) => Some(sast),
                #[allow(unreachable_patterns)]
                _ => None,
            })
            .unwrap()
    }
}

/// Code Security v1.x Configuration
#[derive(Debug, Clone, PartialEq)]
pub struct ConfigFile {
    sast: Option<SastConfig>,
}

impl ConfigFile {
    pub fn sast(&self) -> Option<&SastConfig> {
        self.sast.as_ref()
    }
}

impl From<YamlConfigFile> for ConfigFile {
    fn from(value: YamlConfigFile) -> Self {
        Self {
            sast: value.sast.map(Into::into),
        }
    }
}

/// SAST configuration for v1.0-v1.x (until schema changes)
/// This represents the initial SAST schema. When SAST adds/changes fields in a future
/// minor version, a new YamlSastConfigMinorN struct should be created.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub struct YamlSastConfigMinor0 {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) use_default_rulesets: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) use_rulesets: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) ignore_rulesets: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) ruleset_configs: Option<UniqueKeyMap<YamlRulesetConfig>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) global_config: Option<YamlGlobalConfig>,
}

/// All the different schemas that the "sast" property in the v1.x configuration file can take.
#[derive(Debug, Clone, PartialEq)]
pub enum YamlSastConfig {
    /// SAST schema used from v1.0+
    Minor0(YamlSastConfigMinor0),
}

impl<'de> Deserialize<'de> for YamlSastConfig {
    fn deserialize<D>(_deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Err(serde::de::Error::custom("Use file_v1::parse_yaml()"))
    }
}

impl Serialize for YamlSastConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            YamlSastConfig::Minor0(config) => config.serialize(serializer),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SastConfig {
    pub use_default_rulesets: Option<bool>,
    /// Explicitly enabled rulesets (not including any default rulesets)
    pub use_rulesets: Option<Vec<String>>,
    pub ignore_rulesets: Option<Vec<String>>,
    pub ruleset_configs: Option<IndexMap<String, RulesetConfig>>,
    pub global_config: Option<GlobalConfig>,
}

impl From<YamlSastConfig> for SastConfig {
    fn from(value: YamlSastConfig) -> Self {
        match value {
            YamlSastConfig::Minor0(cfg) => SastConfig {
                use_default_rulesets: cfg.use_default_rulesets,
                use_rulesets: cfg.use_rulesets,
                ignore_rulesets: cfg.ignore_rulesets,
                ruleset_configs: cfg
                    .ruleset_configs
                    .map(|ukm| ukm.0.into_iter().map(|(k, v)| (k, v.into())).collect()),
                global_config: cfg.global_config.map(Into::into),
            },
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Default, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub struct YamlGlobalConfig {
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
pub struct GlobalConfig {
    pub paths: Option<PathConfig>,
    pub use_gitignore: Option<bool>,
    pub max_file_size_kb: Option<u64>,
    pub ignore_generated_files: Option<bool>,
}

impl From<YamlGlobalConfig> for GlobalConfig {
    fn from(value: YamlGlobalConfig) -> Self {
        Self {
            paths: value.path_config.into(),
            use_gitignore: value.use_gitignore,
            max_file_size_kb: value.max_file_size_kb,
            ignore_generated_files: value.ignore_generated_files,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Default, PartialEq)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub struct YamlRulesetConfig {
    #[serde(flatten)]
    pub path_config: YamlPathConfig,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_configs: Option<UniqueKeyMap<YamlRuleConfig>>,
}

impl From<YamlRulesetConfig> for RulesetConfig {
    fn from(value: YamlRulesetConfig) -> Self {
        let paths: Option<PathConfig> = value.path_config.into();
        RulesetConfig {
            paths: paths.unwrap_or_default(),
            rules: value
                .rule_configs
                .map_or_else(IndexMap::default, |ukm| ukm.0)
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Default, PartialEq)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub struct YamlRuleConfig {
    #[serde(flatten)]
    pub path_config: YamlPathConfig,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) arguments: Option<UniqueKeyMap<file_legacy::YamlBySubtree<AnyAsString>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) severity: Option<file_legacy::YamlBySubtree<RuleSeverity>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) category: Option<file_legacy::YamlRuleCategory>,
}

impl From<YamlRuleConfig> for RuleConfig {
    fn from(value: YamlRuleConfig) -> Self {
        let paths: Option<PathConfig> = value.path_config.into();
        RuleConfig {
            paths: paths.unwrap_or_default(),
            arguments: value
                .arguments
                .map_or_else(IndexMap::default, |ukm| ukm.0)
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
            severity: value.severity.map(file_legacy::YamlBySubtree::into),
            category: value.category.map(|c| c.0),
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
            let mut sast: Option<YamlSastConfig> = None;
            match minor {
                0.. => {
                    if let Some(value) = base.sast {
                        let config: YamlSastConfigMinor0 =
                            serde_yaml::from_value(value).map_err(ParseError::Parse)?;
                        let _ = sast.insert(YamlSastConfig::Minor0(config));
                    }
                }
            }

            Ok(YamlConfigFile {
                schema_version: base.schema_version,
                sast,
                secrets: base.secrets,
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
# sast:
secrets: [123]
iac: 1.23
sca:
  one: true
iast: null
";
        let res = parse_yaml(config).expect("should pass validation");
        assert!(res.sast.is_none());
        assert!(res.secrets.is_some());
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
        assert!(matches!(err, ParseError::WrongSchema(v) if v == YamlSchemaVersion::Legacy));

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
}

/// Tests specific 'sast' property within the Code Security v1.x file.
#[cfg(test)]
mod sast_tests {
    use crate::config::common;
    use crate::config::file_v1::{parse_yaml, ConfigFile, GlobalConfig, ParseError, SastConfig};
    use crate::model::rule::RuleCategory;
    use indexmap::IndexMap;

    /// Present fields with "empty" values are deserialized as `Some`.
    #[test]
    fn parse_semantic_some() {
        // language=yaml
        let config = r#"
schema-version: v1.0
sast:
  ignore-rulesets: []
"#;
        let cfg = ConfigFile::from(parse_yaml(config).unwrap());
        assert_eq!(cfg.sast.unwrap().ignore_rulesets, Some(Vec::default()));
    }

    /// All fields in v1.0 SAST config
    #[test]
    fn parse_fields() {
        let config = r#"
schema-version: v1.0
sast:
  use-default-rulesets: true
  use-rulesets:
    - custom-ruleset-1
    - custom-ruleset-2
  ignore-rulesets:
    - some-code-style
  ruleset-configs:
    javascript-best-practices:
      ignore-paths: ["src/abc"]
      rule-configs:
        no-if-else-return:
          category: CODE_STYLE
  global-config:
    max-file-size-kb: 2000
"#;
        let cfg = ConfigFile::from(parse_yaml(config).unwrap());

        assert_eq!(
            cfg.sast.unwrap(),
            SastConfig {
                use_default_rulesets: Some(true),
                use_rulesets: Some(vec![
                    "custom-ruleset-1".to_string(),
                    "custom-ruleset-2".to_string()
                ]),
                ignore_rulesets: Some(vec!["some-code-style".to_string()]),
                ruleset_configs: Some(IndexMap::from([(
                    "javascript-best-practices".to_string(),
                    common::RulesetConfig {
                        paths: common::PathConfig {
                            ignore: vec![common::PathPattern::from("src/abc".to_string())],
                            ..Default::default()
                        },
                        rules: IndexMap::from([(
                            "no-if-else-return".to_string(),
                            common::RuleConfig {
                                category: Some(RuleCategory::CodeStyle),
                                ..Default::default()
                            }
                        )]),
                    }
                )])),
                global_config: Some(GlobalConfig {
                    paths: None,
                    use_gitignore: None,
                    max_file_size_kb: Some(2000),
                    ignore_generated_files: None,
                }),
            }
        )
    }

    /// All relevant Yaml* structs fail if an unknown field is present.
    #[test]
    fn parse_deny_unknown() {
        let unknown_field = "surely-this-is-not-in-the-schema: ...right?";
        let err_msg = "unknown field `surely-this-is-not-in-the-schema`";

        // YamlSastConfig
        let yaml_sast_config = format!(
            "\
schema-version: v1.0
sast:
  {unknown_field}
        "
        );
        // YamlGlobalConfig
        let yaml_global_config = format!(
            "\
schema-version: v1.0
sast:
  global-config:
    {unknown_field}
        "
        );
        // YamlRulesetConfig
        let yaml_ruleset_config = format!(
            "\
schema-version: v1.0
sast:
  ruleset-configs:
    java-security:
      {unknown_field}
        "
        );
        // YamlRuleConfig
        let yaml_rule_config = format!(
            "\
schema-version: v1.0
sast:
  ruleset-configs:
    java-security:
      rule-configs:
        sql-injection:
          {unknown_field}
        "
        );

        for config in &[
            yaml_sast_config,
            yaml_global_config,
            yaml_ruleset_config,
            yaml_rule_config,
        ] {
            let err = parse_yaml(config).unwrap_err();
            assert!(matches!(err, ParseError::Parse(e) if e.to_string().contains(err_msg)));
        }
    }
}
