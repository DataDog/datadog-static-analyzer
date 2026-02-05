// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026 Datadog, Inc.

use crate::config::common::{
    PathConfig, PathPattern, RuleConfig, RulesetConfig, YamlSchemaVersion,
};
use crate::config::file_v1;
use crate::config::file_v1::{AnyAsString, UniqueKeyMap};
use crate::model::rule::RuleSeverity;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub(crate) enum ParseError {
    #[error("unsupported schema `{0}`")]
    WrongSchema(YamlSchemaVersion),
    #[error(transparent)]
    Parse(#[from] serde_yaml::Error),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub(crate) struct YamlConfigFile {
    /// Always equivalent to [`YamlSchemaVersion::V2`]
    pub(crate) schema_version: YamlSchemaVersion,
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

#[derive(Debug, Clone, PartialEq)]
pub struct ConfigFile {
    pub use_default_rulesets: Option<bool>,
    /// Explicitly enabled rulesets (not including any default rulesets)
    pub use_rulesets: Option<Vec<String>>,
    pub ignore_rulesets: Option<Vec<String>>,
    pub ruleset_configs: Option<IndexMap<String, RulesetConfig>>,
    pub global_config: Option<GlobalConfig>,
}

impl From<YamlConfigFile> for ConfigFile {
    fn from(value: YamlConfigFile) -> Self {
        Self {
            use_default_rulesets: value.use_default_rulesets,
            use_rulesets: value.use_rulesets,
            ignore_rulesets: value.ignore_rulesets,
            ruleset_configs: value
                .ruleset_configs
                .map(|ukm| ukm.0.into_iter().map(|(k, v)| (k, v.into())).collect()),
            global_config: value.global_config.map(Into::into),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Default, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub(crate) struct YamlGlobalConfig {
    #[serde(flatten)]
    pub(crate) path_config: YamlPathConfig,
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

#[derive(Debug, Deserialize, Serialize, Default, PartialEq)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub(crate) struct YamlRulesetConfig {
    #[serde(flatten)]
    pub(crate) path_config: YamlPathConfig,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) rule_configs: Option<UniqueKeyMap<YamlRuleConfig>>,
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

#[derive(Debug, Deserialize, Serialize, Default, PartialEq)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub(crate) struct YamlRuleConfig {
    #[serde(flatten)]
    pub(crate) path_config: YamlPathConfig,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) arguments: Option<UniqueKeyMap<file_v1::YamlBySubtree<AnyAsString>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) severity: Option<file_v1::YamlBySubtree<RuleSeverity>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) category: Option<file_v1::YamlRuleCategory>,
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
            severity: value.severity.map(file_v1::YamlBySubtree::into),
            category: value.category.map(|c| c.0),
        }
    }
}

/// A combination of `only-paths` and `ignore-paths` fields, intended to be inlined via [`serde(flatten)`].
#[derive(Debug, Clone, Deserialize, Serialize, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub(crate) struct YamlPathConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) only_paths: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) ignore_paths: Option<Vec<String>>,
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

#[allow(unused)]
pub(crate) fn parse(config_contents: &str) -> Result<ConfigFile, ParseError> {
    let yaml_cfg: YamlConfigFile =
        serde_yaml::from_str(config_contents).map_err(ParseError::Parse)?;

    if yaml_cfg.schema_version != YamlSchemaVersion::V2 {
        return Err(ParseError::WrongSchema(yaml_cfg.schema_version));
    }

    Ok(yaml_cfg.into())
}

#[cfg(test)]
mod tests {
    use crate::config::common;
    use crate::config::common::YamlSchemaVersion;
    use crate::config::file_v2::{parse, ConfigFile, GlobalConfig, ParseError};
    use crate::model::rule::RuleCategory;
    use indexmap::IndexMap;

    /// Optional fields not present are deserialized as None.
    #[test]
    fn parse_optional_fields() {
        let config = r#"
schema-version: v2
"#;
        let res = parse(config).unwrap();
        assert_eq!(
            res,
            ConfigFile {
                use_default_rulesets: None,
                use_rulesets: None,
                ignore_rulesets: None,
                ruleset_configs: None,
                global_config: None,
            }
        );
    }

    /// Present fields with "empty" values are deserialized as `Some`.
    #[test]
    fn parse_semantic_some() {
        let config = r#"
schema-version: v2
ignore-rulesets: []
"#;
        let res = parse(config).unwrap();
        assert_eq!(res.ignore_rulesets, Some(Vec::default()));
    }

    /// All fields new in v2
    #[test]
    fn parse_fields() {
        let config = r#"
schema-version: v2
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
        let res = parse(config).unwrap();

        assert_eq!(
            res,
            ConfigFile {
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
        );
    }

    /// All relevant Yaml* structs fail if an unknown field is present.
    #[test]
    fn parse_deny_unknown() {
        let unknown_field = "surely-this-is-not-in-the-schema: ...right?";
        let err_msg = "unknown field `surely-this-is-not-in-the-schema`";

        // YamlConfigFile
        let yaml_config_file = format!(
            "\
schema-version: v2
{unknown_field}
        "
        );
        // YamlGlobalConfig
        let yaml_global_config = format!(
            "\
schema-version: v2
global-config:
  {unknown_field}
        "
        );
        // YamlRulesetConfig
        let yaml_ruleset_config = format!(
            "\
schema-version: v2
ruleset-configs:
  java-security:
    {unknown_field}
        "
        );
        // YamlRuleConfig
        let yaml_rule_config = format!(
            "\
schema-version: v2
ruleset-configs:
  java-security:
    rule-configs:
      sql-injection:
        {unknown_field}
        "
        );

        for config in &[
            yaml_config_file,
            yaml_global_config,
            yaml_ruleset_config,
            yaml_rule_config,
        ] {
            let err = parse(config).unwrap_err();
            assert!(matches!(err, ParseError::Parse(e) if e.to_string().contains(err_msg)));
        }
    }

    #[test]
    fn parse_no_schema_version() {
        let err = parse("use-default-rulesets: true\n").unwrap_err();
        assert!(
            matches!(err, ParseError::Parse(e) if e.to_string().contains("missing field `schema-version`"))
        );
    }

    #[test]
    fn parse_config_only_v2() {
        let err = parse("schema-version: v1\n").unwrap_err();
        assert!(matches!(err, ParseError::WrongSchema(v) if v == YamlSchemaVersion::V1));
        let err = parse("schema-version: v9\n").unwrap_err();
        assert!(
            matches!(err, ParseError::WrongSchema(v) if v == YamlSchemaVersion::Invalid("v9".to_string()))
        );

        assert!(parse("schema-version: v2\n").is_ok());
    }
}
