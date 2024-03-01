use anyhow::{anyhow, Context, Result};
use serde::de::{Error, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use crate::constants;
use crate::model::config_file::{ConfigFile, PathConfig, RuleConfig, RulesetConfig};

fn parse_config_file(config_contents: &str) -> Result<ConfigFile> {
    let raw_config: RawConfigFile = serde_yaml::from_str(config_contents)?;
    Ok(ConfigFile::from(raw_config))
}

// We first try to read static-analysis.datadog.yml
// If it fails, we try to read static-analysis.datadog.yaml
// If the file does not exist, we return a Ok(None).
// If there is an error reading the file, we return a failure
pub fn read_config_file(path: &str) -> Result<Option<ConfigFile>> {
    let yml_file_path = Path::new(path).join(format!(
        "{}.yml",
        constants::DATADOG_CONFIG_FILE_WITHOUT_PREFIX
    ));
    let yaml_file_path = Path::new(path).join(format!(
        "{}.yaml",
        constants::DATADOG_CONFIG_FILE_WITHOUT_PREFIX
    ));

    // first, static-analysis.datadog.yml
    let mut file = match File::open(yml_file_path) {
        Ok(f) => f,
        Err(e1) if e1.kind() == std::io::ErrorKind::NotFound => {
            // second, static-analysis.datadog.yaml
            match File::open(yaml_file_path) {
                Ok(f) => f,
                Err(e2) if e2.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                otherwise => otherwise?,
            }
        }
        otherwise => otherwise?,
    };
    let mut contents = String::new();

    let size_read = file
        .read_to_string(&mut contents)
        .context("error when reading the configration file")?;
    if size_read == 0 {
        return Err(anyhow!("the config file is empty"));
    }

    Ok(Some(parse_config_file(&contents)?))
}

// The raw configuration file format with legacy fields and other quirks.
#[derive(Deserialize)]
struct RawConfigFile {
    // Configurations for the rulesets.
    #[serde(deserialize_with = "deserialize_rulesetconfigs")]
    rulesets: HashMap<String, RawRulesetConfig>,
    // Paths to include/exclude from analysis.
    #[serde(flatten)]
    paths: RawPathConfig,
    // For backwards compatibility. Its content will be added to paths.ignore.
    #[serde(rename = "ignore-paths", default)]
    ignore_paths: Vec<String>,
    // Ignore all the paths in the .gitignore file.
    #[serde(rename = "ignore-gitignore")]
    ignore_gitignore: Option<bool>,
    // Analyze only files up to this size.
    #[serde(rename = "max-file-size-kb")]
    max_file_size_kb: Option<u64>,
}

impl From<RawConfigFile> for ConfigFile {
    fn from(value: RawConfigFile) -> Self {
        ConfigFile {
            rulesets: {
                let mut rulesets = HashMap::new();
                for (k, v) in value.rulesets {
                    rulesets.insert(k, RulesetConfig::from(v));
                }
                rulesets
            },
            paths: {
                let mut paths = PathConfig::from(value.paths);
                paths.ignore.extend(value.ignore_paths);
                paths
            },
            ignore_gitignore: value.ignore_gitignore,
            max_file_size_kb: value.max_file_size_kb,
        }
    }
}

// Configuration for a ruleset.
#[derive(Deserialize, Default)]
struct RawRulesetConfig {
    // Paths to include/exclude for all rules in this ruleset.
    #[serde(flatten)]
    pub paths: RawPathConfig,
    // Rule-specific configurations.
    #[serde(default, deserialize_with = "deserialize_ruleconfigs")]
    pub rules: HashMap<String, RawRuleConfig>,
}

impl From<RawRulesetConfig> for RulesetConfig {
    fn from(value: RawRulesetConfig) -> Self {
        RulesetConfig {
            paths: PathConfig::from(value.paths),
            rules: {
                let mut rules = HashMap::new();
                for (k, v) in value.rules {
                    rules.insert(k, RuleConfig::from(v));
                }
                rules
            },
        }
    }
}

// Configuration for a single rule.
#[derive(Deserialize, Default)]
struct RawRuleConfig {
    // Paths to include/exclude for this rule.
    #[serde(flatten)]
    pub paths: RawPathConfig,
}

impl From<RawRuleConfig> for RuleConfig {
    fn from(value: RawRuleConfig) -> Self {
        RuleConfig {
            paths: PathConfig::from(value.paths),
        }
    }
}

#[derive(Deserialize, Default)]
struct RawPathConfig {
    // Analyze only these directories and patterns.
    pub only: Option<Vec<String>>,
    // Do not analyze any of these directories and patterns.
    #[serde(default)]
    pub ignore: Vec<String>,
}

impl From<RawPathConfig> for PathConfig {
    fn from(value: RawPathConfig) -> Self {
        PathConfig {
            only: value.only,
            ignore: value.ignore,
        }
    }
}

/// Special deserializer for a `RulesetConfig` map.
///
/// For backwards compatibility, we want to support lists of strings and maps from name to ruleset
/// config.
/// Lists of strings produce maps of empty `RulesetConfig`s.
/// Duplicate rulesets are rejected.
fn deserialize_rulesetconfigs<'de, D>(
    deserializer: D,
) -> std::result::Result<HashMap<String, RawRulesetConfig>, D::Error>
where
    D: Deserializer<'de>,
{
    struct RulesetConfigsVisitor {}
    impl<'de> Visitor<'de> for RulesetConfigsVisitor {
        type Value = HashMap<String, RawRulesetConfig>;

        fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
            formatter.write_str("a list of strings or map from string to ruleset configuration")
        }

        /// Deserializes a list of strings.
        fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut out = HashMap::new();
            while let Some(nrc) = seq.next_element::<NamedRulesetConfig>()? {
                if out.insert(nrc.name.clone(), nrc.cfg).is_some() {
                    return Err(Error::custom(format!("duplicate ruleset: {}", nrc.name)));
                }
            }
            Ok(out)
        }

        /// Deserializes a map of string to `RulesetConfig`.
        fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            let mut out = HashMap::new();
            while let Some((k, v)) = map.next_entry::<String, RawRulesetConfig>()? {
                if out.insert(k.clone(), v).is_some() {
                    return Err(Error::custom(format!("found duplicate ruleset: {}", k)));
                }
            }
            Ok(out)
        }
    }
    deserializer.deserialize_any(RulesetConfigsVisitor {})
}

/// Holder for ruleset configurations specified in lists.
struct NamedRulesetConfig {
    name: String,
    cfg: RawRulesetConfig,
}

/// Special deserializer for ruleset list items.
///
/// As we've changed the format, we are going to get a mixture of old format configurations,
/// new format configurations, and configurations that have been converted but have syntax errors.
///
/// To be friendly, we try extra hard to parse the configuration file the user intended, even in
/// the face of syntax errors:
///
/// This is the modern syntax:
/// ```yaml
/// rulesets:
///   ruleset1:
///   ruleset2:
///     ignore:
///       - "foo"
///   ruleset3:
/// ```
/// This is the old syntax:
/// ```yaml
/// rulesets:
///   - ruleset1
///   - ruleset2
///   - ruleset3
/// ```
/// This is an invalid syntax that we try to parse here:
/// ```yaml
/// rulesets:
///   - ruleset1
///   - ruleset2:
///       ignore:
///         - "foo"
///   - ruleset3:
///     ignore:
///       - "foo"
/// ```
/// (Note the indentation for the difference between the last two rulesets.)
impl<'de> Deserialize<'de> for NamedRulesetConfig {
    fn deserialize<D>(deserializer: D) -> std::result::Result<NamedRulesetConfig, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct NamedRulesetConfigVisitor {}
        impl<'de> Visitor<'de> for NamedRulesetConfigVisitor {
            type Value = NamedRulesetConfig;
            fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                formatter.write_str("a string or ruleset configuration")
            }

            fn visit_str<E>(self, v: &str) -> std::result::Result<Self::Value, E>
            where
                E: Error,
            {
                self.visit_string(v.to_string())
            }

            fn visit_string<E>(self, v: String) -> std::result::Result<Self::Value, E>
            where
                E: Error,
            {
                Ok(NamedRulesetConfig {
                    name: v,
                    cfg: RawRulesetConfig::default(),
                })
            }

            fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut out = match map.next_entry::<String, RawRulesetConfig>()? {
                    None => {
                        return Err(Error::missing_field("name"));
                    }
                    Some((k, v)) => NamedRulesetConfig { name: k, cfg: v },
                };
                // If the user forgot to indent, we populate the object field by field.
                while let Some(x) = map.next_key::<String>()? {
                    match x.as_str() {
                        "only" => {
                            if out.cfg.paths.only.is_some() {
                                return Err(Error::duplicate_field("only"));
                            } else {
                                out.cfg.paths.only = Some(map.next_value()?);
                            }
                        }
                        "ignore" => {
                            if !out.cfg.paths.ignore.is_empty() {
                                return Err(Error::duplicate_field("ignore"));
                            } else {
                                out.cfg.paths.ignore = map.next_value()?;
                            }
                        }
                        "rules" => {
                            if !out.cfg.rules.is_empty() {
                                return Err(Error::duplicate_field("rules"));
                            } else {
                                out.cfg.rules = map.next_value()?;
                            }
                        }
                        "" => {
                            // Ignore empty keys
                        }
                        otherwise => {
                            return Err(Error::custom(format!("unknown field: {}", otherwise)));
                        }
                    }
                }
                Ok(out)
            }
        }
        deserializer.deserialize_any(NamedRulesetConfigVisitor {})
    }
}

/// Deserializer for a `RuleConfig` map which rejects duplicate rules.
fn deserialize_ruleconfigs<'de, D>(
    deserializer: D,
) -> std::result::Result<HashMap<String, RawRuleConfig>, D::Error>
where
    D: Deserializer<'de>,
{
    struct RuleConfigVisitor {}
    impl<'de> Visitor<'de> for RuleConfigVisitor {
        type Value = HashMap<String, RawRuleConfig>;

        fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
            formatter.write_str("an optional map from string to rule configuration")
        }

        /// Deserializes a map of string to `RuleConfig`.
        fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            let mut out = HashMap::new();
            while let Some((k, v)) = map.next_entry::<String, RawRuleConfig>()? {
                if out.insert(k.clone(), v).is_some() {
                    return Err(Error::custom(format!("found duplicate rule: {}", k)));
                }
            }
            Ok(out)
        }
    }
    deserializer.deserialize_any(RuleConfigVisitor {})
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::config_file::{ConfigFile, PathConfig, RuleConfig, RulesetConfig};
    use std::collections::HashMap;

    // `rulesets` parsed as a list of ruleset names
    #[test]
    fn test_parse_rulesets_as_list_of_strings() {
        let data = r#"
rulesets:
  - python-security
  - go-best-practices
    "#;
        let expected = ConfigFile {
            rulesets: HashMap::from([
                ("python-security".to_string(), RulesetConfig::default()),
                ("go-best-practices".to_string(), RulesetConfig::default()),
            ]),
            ..ConfigFile::default()
        };

        let res = parse_config_file(data);
        assert_eq!(expected, res.unwrap());
    }

    // `rulesets` parsed as a map from rule name to config.
    #[test]
    fn test_parse_rulesets_as_map() {
        let data = r#"
rulesets:
  python-security:
  go-best-practices:
    only:
      - "one/two"
      - "foo/**/*.go"
    ignore:
      - "tres/cuatro"
      - "bar/**/*.go"
  java-security:
    rules:
      random-iv:
    "#;
        let expected = ConfigFile {
            rulesets: HashMap::from([
                ("python-security".to_string(), RulesetConfig::default()),
                (
                    "go-best-practices".to_string(),
                    RulesetConfig {
                        paths: PathConfig {
                            only: Some(vec!["one/two".to_string(), "foo/**/*.go".to_string()]),
                            ignore: vec!["tres/cuatro".to_string(), "bar/**/*.go".to_string()],
                        },
                        rules: HashMap::new(),
                    },
                ),
                (
                    "java-security".to_string(),
                    RulesetConfig {
                        paths: PathConfig::default(),
                        rules: HashMap::from([("random-iv".to_string(), RuleConfig::default())]),
                    },
                ),
            ]),
            ..ConfigFile::default()
        };

        let res = parse_config_file(data);
        assert_eq!(expected, res.unwrap());
    }

    // Parse improperly formatted YAML where the rulesets are lists of maps
    // or mixed lists of strings and maps.
    #[test]
    fn test_parse_rulesets_as_list_of_strings_and_maps() {
        let data = r#"
rulesets:
  - c-best-practices
  - rust-best-practices:
  - go-best-practices:
    only:
      - "foo"
  - python-best-practices:
      ignore:
        - "bar"
    "#;

        let expected = ConfigFile {
            rulesets: HashMap::from([
                ("c-best-practices".to_string(), RulesetConfig::default()),
                ("rust-best-practices".to_string(), RulesetConfig::default()),
                (
                    "go-best-practices".to_string(),
                    RulesetConfig {
                        paths: PathConfig {
                            only: Some(vec!["foo".to_string()]),
                            ignore: vec![],
                        },
                        ..Default::default()
                    },
                ),
                (
                    "python-best-practices".to_string(),
                    RulesetConfig {
                        paths: PathConfig {
                            only: None,
                            ignore: vec!["bar".to_string()],
                        },
                        ..Default::default()
                    },
                ),
            ]),
            ..ConfigFile::default()
        };

        let res = parse_config_file(data);
        assert_eq!(expected, res.unwrap());
    }

    // Cannot have repeated ruleset configurations.
    #[test]
    fn test_cannot_parse_rulesets_with_repeated_names() {
        let data = r#"
rulesets:
  - go-best-practices
  - go-security
  - go-best-practices
    "#;

        let res = parse_config_file(data);
        assert!(res.is_err());
        let data = r#"
rulesets:
  go-best-practices:
  go-security:
  go-best-practices:
    "#;

        let res = parse_config_file(data);
        assert!(res.is_err());
    }

    // Rule definitions can be parsed.
    #[test]
    fn test_parse_rules() {
        let data = r#"
rulesets:
  python-security:
    rules:
      no-eval:
        only:
          - "py/**"
        ignore:
          - "py/insecure/**"
    "#;
        let expected = ConfigFile {
            rulesets: HashMap::from([(
                "python-security".to_string(),
                RulesetConfig {
                    paths: PathConfig::default(),
                    rules: HashMap::from([(
                        "no-eval".to_string(),
                        RuleConfig {
                            paths: PathConfig {
                                only: Some(vec!["py/**".to_string()]),
                                ignore: vec!["py/insecure/**".to_string()],
                            },
                        },
                    )]),
                },
            )]),
            ..ConfigFile::default()
        };

        let res = parse_config_file(data);
        assert_eq!(expected, res.unwrap());
    }

    // Rules cannot be specified as lists of strings or maps.
    #[test]
    fn test_cannot_parse_rules_as_list() {
        let data = r#"
rulesets:
  python-security:
    rules:
      - no-eval
    "#;

        let res = parse_config_file(data);
        assert!(res.is_err());

        let data = r#"
rulesets:
  python-security:
    rules:
      - no-eval:
          only:
            - "py/**"
          ignore:
            - "py/insecure/**"
    "#;

        let res = parse_config_file(data);
        assert!(res.is_err());
    }

    // Rules cannot be repeated.
    #[test]
    fn test_cannot_parse_repeated_rules() {
        let data = r#"
rulesets:
  python-security:
    rules:
      no-eval:
        only:
          - "foo"
      no-eval:
        ignore:
          - "bar"
    "#;

        let res = parse_config_file(data);
        assert!(res.is_err());
    }

    // test with everything
    #[test]
    fn test_parse_all_other_options() {
        let data = r#"
rulesets:
  - python-security
only:
  - "py/**/foo/*.py"
ignore:
  - "py/testing/*.py"
ignore-paths:
  - "**/test/**"
  - path1
ignore-gitignore: false
max-file-size-kb: 512
    "#;

        let expected = ConfigFile {
            rulesets: HashMap::from([("python-security".to_string(), RulesetConfig::default())]),
            paths: PathConfig {
                only: Some(vec!["py/**/foo/*.py".to_string()]),
                ignore: vec![
                    "py/testing/*.py".to_string(),
                    "**/test/**".to_string(),
                    "path1".to_string(),
                ],
            },
            ignore_gitignore: Some(false),
            max_file_size_kb: Some(512),
        };

        let res = parse_config_file(data);
        assert_eq!(expected, res.unwrap());
    }

    // No ruleset available in the data means that we have no configuration file
    // whatsoever and we should return Err
    #[test]
    fn test_parse_no_rulesets() {
        let data = r#"
    "#;
        let res = parse_config_file(data);
        assert!(res.is_err());
    }
}
