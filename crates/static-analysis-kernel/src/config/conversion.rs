// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026 Datadog, Inc.

use crate::config::common::YamlSchemaVersion;
use crate::config::file_legacy::UniqueKeyMap;
use crate::config::{file_legacy, file_v1};
use indexmap::IndexMap;

impl From<file_legacy::YamlConfigFile> for file_v1::YamlConfigFile {
    fn from(value: file_legacy::YamlConfigFile) -> Self {
        let mut combined_ignores = value.paths.ignore;
        if let Some(paths) = value.ignore_paths {
            combined_ignores.extend(paths)
        }

        let mut use_rulesets = Vec::<String>::with_capacity(value.rulesets.0.len());
        let mut ruleset_configs = IndexMap::<String, file_v1::YamlRulesetConfig>::new();

        for legacy_ruleset_cfg in value.rulesets.0 {
            let ruleset_cfg: file_v1::YamlRulesetConfig = legacy_ruleset_cfg.cfg.into();
            if ruleset_cfg != file_v1::YamlRulesetConfig::default() {
                let _ = ruleset_configs.insert(legacy_ruleset_cfg.name.clone(), ruleset_cfg);
            }
            use_rulesets.push(legacy_ruleset_cfg.name);
        }

        let global_config = file_v1::YamlGlobalConfig {
            path_config: file_v1::YamlPathConfig {
                only_paths: value.paths.only,
                ignore_paths: (!combined_ignores.is_empty()).then_some(combined_ignores),
            },
            // v1.0 `use_gitignore` defaults to true and is logically equivalent to !(legacy `ignore_gitignore`).
            // Thus, it should only be Some if the legacy `ignore_gitignore` is non-default (i.e. "false").
            //
            // Thus, only set to Some if legacy `ignore_gitignore` is true.
            use_gitignore: (value.ignore_gitignore == Some(true)).then_some(false),
            ignore_generated_files: value.ignore_generated_files,
            max_file_size_kb: value.max_file_size_kb,
        };

        let sast_minor0 = file_v1::YamlSastConfigMinor0 {
            // (Going from legacy -> v1.0 always implies an explicit disabling of default rulesets)
            use_default_rulesets: Some(false),
            use_rulesets: (!use_rulesets.is_empty()).then_some(use_rulesets),
            ignore_rulesets: None,
            // (ruleset_configs came from file_legacy::YamlRulesetList, which enforces key uniqueness, so
            // we can manually construct UniqueKeyMap without validation).
            ruleset_configs: (!ruleset_configs.is_empty()).then_some(UniqueKeyMap(ruleset_configs)),
            global_config: (global_config != file_v1::YamlGlobalConfig::default())
                .then_some(global_config),
        };

        Self {
            schema_version: YamlSchemaVersion::MajorMinor((1, 0)),
            sast: Some(file_v1::YamlSastConfig::Minor0(sast_minor0)),
            secrets: None,
            iac: None,
            sca: None,
            iast: None,
        }
    }
}

impl From<file_legacy::YamlPathConfig> for file_v1::YamlPathConfig {
    fn from(value: file_legacy::YamlPathConfig) -> Self {
        Self {
            only_paths: value.only,
            ignore_paths: (!value.ignore.is_empty()).then_some(value.ignore),
        }
    }
}

impl From<file_legacy::YamlRuleConfig> for file_v1::YamlRuleConfig {
    fn from(value: file_legacy::YamlRuleConfig) -> Self {
        Self {
            path_config: value.paths.into(),
            arguments: (!value.arguments.0.is_empty()).then_some(value.arguments),
            severity: value.severity,
            category: value.category,
        }
    }
}

impl From<file_legacy::YamlRulesetConfig> for file_v1::YamlRulesetConfig {
    fn from(value: file_legacy::YamlRulesetConfig) -> Self {
        Self {
            path_config: value.paths.into(),
            rule_configs: (!value.rules.0.is_empty()).then(|| {
                UniqueKeyMap(
                    value
                        .rules
                        .0
                        .into_iter()
                        .map(|(name, config)| (name, config.into()))
                        .collect::<IndexMap<_, _>>(),
                )
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::config::common::YamlSchemaVersion;
    use crate::config::{file_legacy, file_v1};
    use crate::model::rule::{RuleCategory, RuleSeverity};
    use indexmap::IndexMap;

    /// Returns a legacy schema with `rulesets: [java-security]` followed by the provided content.
    fn legacy_template(content: &str) -> String {
        format!(
            "\
schema-version: v1
rulesets:
  - java-security
{content}
"
        )
    }

    /// Shorthand to deserialize a valid legacy config string into a v1.0 YamlConfigFile
    fn to_v1_0(cfg: impl AsRef<str>) -> file_v1::YamlConfigFile {
        serde_yaml::from_str::<file_legacy::YamlConfigFile>(cfg.as_ref())
            .unwrap()
            .into()
    }

    #[test]
    fn yaml_path_config_from() {
        let v2 = file_v1::YamlPathConfig::from(file_legacy::YamlPathConfig {
            only: Some(vec!["src/a".to_string()]),
            ignore: vec!["src/a/z".to_string()],
        });
        assert_eq!(
            v2,
            file_v1::YamlPathConfig {
                only_paths: Some(vec!["src/a".to_string()]),
                ignore_paths: Some(vec!["src/a/z".to_string()]),
            }
        );
        // Empty vec is translated to None.
        let v2 = file_v1::YamlPathConfig::from(file_legacy::YamlPathConfig {
            only: Some(vec!["src/a".to_string()]),
            ignore: vec![],
        });
        assert!(v2.ignore_paths.is_none());
    }

    #[test]
    fn yaml_rule_config_from() {
        #[rustfmt::skip]
        let argument_map = file_legacy::UniqueKeyMap(IndexMap::from([
            ("src/a".to_string(), file_legacy::YamlBySubtree(IndexMap::from([("arg_name".to_string(), file_legacy::AnyAsString::Str("some_value".to_string()))]))),
        ]));
        #[rustfmt::skip]
        let severity_map = file_legacy::YamlBySubtree(IndexMap::<String, RuleSeverity>::from([
            ("src/a".to_string(), RuleSeverity::Error)
        ]));
        let category = file_legacy::YamlRuleCategory(RuleCategory::Security);
        let v2 = file_v1::YamlRuleConfig::from(file_legacy::YamlRuleConfig {
            paths: Default::default(),
            arguments: argument_map.clone(),
            severity: Some(severity_map.clone()),
            category: Some(category),
        });
        assert_eq!(v2.arguments, Some(argument_map));
        assert_eq!(v2.severity, Some(severity_map));
        assert_eq!(v2.category, Some(category));

        // Empty map is translated to None.
        let argument_map = file_legacy::UniqueKeyMap(IndexMap::default());
        let v2 = file_v1::YamlRuleConfig::from(file_legacy::YamlRuleConfig {
            paths: Default::default(),
            arguments: argument_map,
            severity: None,
            category: None,
        });
        assert!(v2.arguments.is_none());
    }

    #[test]
    fn yaml_ruleset_config_from() {
        // Empty map is translated to None.
        let v2 = file_v1::YamlRulesetConfig::from(file_legacy::YamlRulesetConfig {
            paths: Default::default(),
            rules: file_legacy::UniqueKeyMap(IndexMap::default()),
        });
        assert!(v2.rule_configs.is_none());
    }

    /// Baseline conversion:
    /// * `schema-version` is always v1.0
    /// * sast `use-default-rulesets` is always false.
    #[test]
    fn baseline() {
        let cfg = to_v1_0(legacy_template(""));
        assert_eq!(cfg.schema_version, YamlSchemaVersion::MajorMinor((1, 0)));
        assert_eq!(cfg.sast0().use_default_rulesets, Some(false));
    }

    /// legacy `ignore` and `ignore-paths` are concatenated, if present.
    #[test]
    fn ignore_paths_concat() {
        let cfg = to_v1_0(legacy_template(""));
        assert!(cfg.sast0().global_config.is_none());

        let cfg = to_v1_0(legacy_template(
            // language=yaml
            "
ignore:
  - src/a
",
        ));
        let global_config = cfg.sast0().global_config.clone().unwrap();
        assert_eq!(
            global_config.path_config.ignore_paths.unwrap(),
            vec!["src/a"]
        );

        let cfg = to_v1_0(legacy_template(
            // language=yaml
            "
ignore-paths:
  - src/b
",
        ));
        let global_config = cfg.sast0().global_config.clone().unwrap();
        assert_eq!(
            global_config.path_config.ignore_paths.unwrap(),
            vec!["src/b"]
        );

        let cfg = to_v1_0(legacy_template(
            // language=yaml
            "
ignore:
  - src/a
ignore-paths:
  - src/b
",
        ));
        let global_config = cfg.sast0().global_config.clone().unwrap();
        assert_eq!(
            global_config.path_config.ignore_paths.unwrap(),
            vec!["src/a", "src/b"]
        );
    }

    /// v1.0 `use-gitignore` is only present if legacy `ignore-gitignore` was true.
    #[test]
    fn gitignore_semantics() {
        let cfg = to_v1_0(legacy_template(""));
        assert!(cfg.sast0().global_config.is_none());

        let cfg = to_v1_0(legacy_template(
            // language=yaml
            "
ignore-gitignore: false
",
        ));
        assert!(cfg.sast0().global_config.is_none());

        let cfg = to_v1_0(legacy_template(
            // language=yaml
            "
ignore-gitignore: true
",
        ));
        let global_config = cfg.sast0().global_config.clone().unwrap();
        assert_eq!(global_config.use_gitignore, Some(false));
    }

    #[test]
    fn global_config() {
        let cfg = to_v1_0(legacy_template(""));
        assert!(cfg.sast0().global_config.is_none());

        let cfg = to_v1_0(legacy_template(
            // language=yaml
            "
only:
  - src/a
ignore:
  - src/a/z
ignore-generated-files: true
max-file-size-kb: 500
",
        ));
        let global_config = cfg.sast0().global_config.as_ref().unwrap();
        assert_eq!(
            global_config.path_config.only_paths.as_ref().unwrap(),
            &vec!["src/a"]
        );
        assert_eq!(
            global_config.path_config.ignore_paths.as_ref().unwrap(),
            &vec!["src/a/z"]
        );
        assert_eq!(global_config.ignore_generated_files, Some(true));
        assert_eq!(global_config.max_file_size_kb, Some(500));
    }

    /// v1.0 `use-rulesets` and `ruleset-configs` are constructed correctly
    #[test]
    fn ruleset_configs_use_rulesets_split() {
        let cfg = to_v1_0(
            // language=yaml
            "
schema-version: v1
rulesets:
  - java-security
  - python-security
",
        );

        assert_eq!(
            cfg.sast0().use_rulesets.as_ref().unwrap(),
            &vec!["java-security", "python-security"]
        );
        assert!(cfg.sast0().ruleset_configs.is_none());

        let cfg = to_v1_0(
            // language=yaml
            "
schema-version: v1
rulesets:
  - java-security
  # (Note the colon, indicating an empty config)
  - python-security:
",
        );
        assert_eq!(
            cfg.sast0().use_rulesets.as_ref().unwrap(),
            &vec!["java-security", "python-security"]
        );
        assert!(cfg.sast0().ruleset_configs.is_none());

        let cfg = to_v1_0(
            // language=yaml
            "
schema-version: v1
rulesets:
  - java-security
  - python-security:
    only:
      - src/a
",
        );
        assert_eq!(
            cfg.sast0().use_rulesets.as_ref().unwrap(),
            &vec!["java-security", "python-security"]
        );
        assert_eq!(
            &cfg.sast0().ruleset_configs.as_ref().unwrap().0,
            &IndexMap::from([(
                "python-security".to_string(),
                file_v1::YamlRulesetConfig {
                    path_config: file_v1::YamlPathConfig {
                        only_paths: Some(vec!["src/a".to_string()]),
                        ignore_paths: None,
                    },
                    rule_configs: None,
                }
            )])
        )
    }
}
