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
    pub sast: Option<YamlSastConfig>,
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
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
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

impl Default for YamlSastConfig {
    fn default() -> Self {
        // This should always be the latest minor version implemented
        Self::Minor0(Default::default())
    }
}

const WILDCARD_IGNORE: &str = "**";

impl YamlSastConfig {
    /// Adds an ignore for the provided rule, returning true if it was added, or false if already ignored.
    pub fn add_rule_ignore(&mut self, rule_id: impl AsRef<str>) -> Result<bool, &'static str> {
        let rule_config = match self {
            YamlSastConfig::Minor0(cfg) => {
                let Some((ruleset_name, rule_name)) = rule_id.as_ref().split_once('/') else {
                    return Err("invalid rule_id");
                };
                let map = cfg.ruleset_configs.get_or_insert_default();
                let ruleset_config = map.0.entry(ruleset_name.to_string()).or_default();
                ruleset_config
                    .rule_configs
                    .get_or_insert_default()
                    .0
                    .entry(rule_name.to_string())
                    .or_default()
            }
        };
        let has_ignore = rule_config
            .path_config
            .ignore_paths
            .as_ref()
            .is_some_and(|paths| paths.iter().any(|s| s == WILDCARD_IGNORE));

        Ok(if has_ignore {
            false
        } else {
            rule_config.path_config.ignore_paths = Some(vec!["**".to_string()]);
            true
        })
    }

    /// Adds the listed rulesets to the `use-rulesets` array, returning true if at least one was inserted.
    pub fn add_rulesets(&mut self, rulesets: &[impl AsRef<str>]) -> bool {
        if rulesets.is_empty() {
            return false;
        }
        let list = match self {
            YamlSastConfig::Minor0(cfg) => cfg
                .use_rulesets
                .get_or_insert_with(|| Vec::with_capacity(rulesets.len())),
        };
        let mut did_insert = false;
        for ruleset_name in rulesets {
            if !list.iter().any(|name| ruleset_name.as_ref() == name) {
                list.push(ruleset_name.as_ref().to_string());
                did_insert = true;
            }
        }
        did_insert
    }

    /// Returns a reference the `use-rulesets` list.
    pub fn use_rulesets(&self) -> Option<&[String]> {
        match self {
            YamlSastConfig::Minor0(cfg) => cfg.use_rulesets.as_deref(),
        }
    }

    /// Returns a reference to the `global-config`.
    pub fn global_config(&self) -> Option<&YamlGlobalConfig> {
        match self {
            YamlSastConfig::Minor0(cfg) => cfg.global_config.as_ref(),
        }
    }
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
    /// The list of `use-rulesets` from the configuration file
    use_rulesets: Option<Vec<String>>,
    pub ignore_rulesets: Vec<String>,
    pub ruleset_configs: Option<IndexMap<String, RulesetConfig>>,
    pub global_config: Option<GlobalConfig>,
}

impl SastConfig {
    /// Returns all rulesets explicitly requested by this configuration (excluding
    /// those in [`ignore_rulesets`](Self::ignore_rulesets))
    pub fn explicit_rulesets(&self) -> impl Iterator<Item = &str> + '_ {
        self.use_rulesets
            .iter()
            .flatten()
            .filter(|&ruleset| !self.ignore_rulesets.contains(ruleset))
            .map(String::as_str)
    }
}

impl From<YamlSastConfig> for SastConfig {
    fn from(value: YamlSastConfig) -> Self {
        match value {
            YamlSastConfig::Minor0(cfg) => SastConfig {
                use_default_rulesets: cfg.use_default_rulesets,
                use_rulesets: cfg.use_rulesets,
                ignore_rulesets: cfg.ignore_rulesets.unwrap_or_default(),
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
    use crate::config::file_v1::{
        parse_yaml, ConfigFile, GlobalConfig, ParseError, SastConfig, YamlRuleConfig,
        YamlSastConfig, YamlSastConfigMinor0,
    };
    use crate::model::rule::RuleCategory;
    use indexmap::IndexMap;

    /// Helper function to extract a mutable reference to the config for the rule_id provided.
    #[rustfmt::skip]
    fn minor0_rule_cfg<'a>(
        sast: &'a mut YamlSastConfig,
        rule_id: &str,
    ) -> Option<&'a mut YamlRuleConfig> {
        let (ruleset_name, rule_name) = rule_id.split_once("/")?;
        let YamlSastConfig::Minor0(ref mut minor0) = sast;
        minor0
            .ruleset_configs.as_mut()?.0
            .get_mut(ruleset_name)?
            .rule_configs.as_mut()?.0
            .get_mut(rule_name)
    }

    /// Present fields with "empty" values are deserialized as `Some`.
    #[test]
    fn parse_semantic_some() {
        // language=yaml
        let config = r#"
schema-version: v1.0
sast:
  use-rulesets: []
"#;
        let cfg = ConfigFile::from(parse_yaml(config).unwrap());
        assert_eq!(cfg.sast.unwrap().use_rulesets, Some(Vec::default()));
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
                ignore_rulesets: vec!["some-code-style".to_string()],
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

    #[rustfmt::skip]
    #[test]
    fn ignore_rule() {
        let ruleset_name = "java-security";
        let rule_name = "sql-injection";
        let rule_id = format!("{ruleset_name}/{rule_name}");

        let mut sast = YamlSastConfig::Minor0(YamlSastConfigMinor0::default());
        assert!(matches!(sast.add_rule_ignore(ruleset_name), Err(e) if e == "invalid rule_id"));
        let res = sast.add_rule_ignore(&rule_id);
        assert_eq!(res, Ok(true));

        assert_eq!(
            minor0_rule_cfg(&mut sast, &rule_id).unwrap().path_config.ignore_paths.as_ref().unwrap(),
            &["**"][..]
        );
        let res = sast.add_rule_ignore(&rule_id);
        assert_eq!(res, Ok(false));

        minor0_rule_cfg(&mut sast, &rule_id).unwrap().path_config
            .ignore_paths.as_mut().unwrap()
            .push("other/path".to_string());
        // Checks for vec item, not vec equality
        let res = sast.add_rule_ignore(&rule_id);
        assert_eq!(res, Ok(false));
        assert_eq!(
            minor0_rule_cfg(&mut sast, &rule_id).unwrap().path_config.ignore_paths.as_ref().unwrap(),
            &["**", "other/path"][..]
        );
    }

    /// The `use-rulesets` vec isn't instantiated unless at least one ruleset is passed in.
    #[test]
    fn add_rulesets_empty() {
        let mut sast = YamlSastConfig::Minor0(YamlSastConfigMinor0::default());

        assert!(sast.use_rulesets().is_none());
        sast.add_rulesets(&[] as &[&str]);
        assert!(sast.use_rulesets().is_none());
    }

    /// Adding works, and no duplicates are added.
    #[test]
    fn add_rulesets_but_no_duplicates() {
        let minor0 = YamlSastConfigMinor0 {
            use_rulesets: Some(vec!["existing-rs".to_string()]),
            ..Default::default()
        };
        let mut sast = YamlSastConfig::Minor0(minor0);

        sast.add_rulesets(&["new-rs", "existing-rs", "new-rs"]);
        assert_eq!(sast.use_rulesets().unwrap(), &["existing-rs", "new-rs"][..]);
    }
}
