use anyhow::Result;
use indexmap::IndexMap;
use serde::de::value::MapAccessDeserializer;
use serde::de::{Error, MapAccess, Unexpected, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_yaml::Value;
use std::fmt;
use std::fmt::{Display, Formatter};

use crate::model::config_file::{
    ArgumentValues, ConfigFile, PathPattern, RuleConfig, RulesetConfig,
};
use crate::model::rule::RuleCategory;

pub fn parse_config_file(config_contents: &str) -> Result<ConfigFile> {
    Ok(serde_yaml::from_str(config_contents)?)
}

pub fn config_file_to_yaml(cfg: &ConfigFile) -> Result<String> {
    Ok(serde_yaml::to_string(cfg)?)
}

const SCHEMA_VERSION: &str = "v1";

pub fn deserialize_schema_version<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let v = String::deserialize(deserializer)?;
    if v != SCHEMA_VERSION {
        Err(Error::invalid_value(
            Unexpected::Str(&v),
            &format!("\"{}\"", SCHEMA_VERSION).as_str(),
        ))
    } else {
        Ok(v.to_string())
    }
}

pub fn get_default_schema_version() -> String {
    SCHEMA_VERSION.to_string()
}

/// Special deserializer for a `RulesetConfig` map.
/// Duplicate rulesets are rejected.
pub fn deserialize_ruleset_configs<'de, D>(
    deserializer: D,
) -> Result<IndexMap<String, RulesetConfig>, D::Error>
where
    D: Deserializer<'de>,
{
    let mut out = IndexMap::new();
    let cfgs: Vec<NamedRulesetConfig> = Vec::deserialize(deserializer)?;
    for nrc in cfgs {
        if out.insert(nrc.name.clone(), nrc.cfg).is_some() {
            return Err(Error::custom(format!("duplicate ruleset: {}", nrc.name)));
        }
    }
    if out.is_empty() {
        return Err(Error::custom("no rulesets were specified"));
    }
    Ok(out)
}

pub fn serialize_ruleset_configs<S: Serializer>(
    rulesets: &IndexMap<String, RulesetConfig>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    rulesets
        .iter()
        .map(|(key, value)| NamedRulesetConfig {
            name: key.clone(),
            cfg: value.clone(),
        })
        .collect::<Vec<_>>()
        .serialize(serializer)
}

/// Holder for ruleset configurations specified in lists.
struct NamedRulesetConfig {
    name: String,
    cfg: RulesetConfig,
}

/// Special deserializer for ruleset list items.
///
/// ```yaml
/// rulesets:
///   - ruleset1
///   - ruleset2:
///   - ruleset3:
///     ignore:
///       - "foo"
/// ```
impl<'de> Deserialize<'de> for NamedRulesetConfig {
    fn deserialize<D>(deserializer: D) -> Result<NamedRulesetConfig, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Fields {
            #[serde(flatten)]
            cfg: RulesetConfig,
            #[serde(flatten)]
            #[serde(default)]
            remaining_fields: IndexMap<String, Value>,
        }
        struct StringOrStruct {}
        impl<'de> Visitor<'de> for StringOrStruct {
            type Value = NamedRulesetConfig;

            fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                formatter.write_str("string or ruleset configuration")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                Ok(NamedRulesetConfig {
                    name: v.to_string(),
                    cfg: RulesetConfig::default(),
                })
            }

            fn visit_map<A>(self, map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let m = Fields::deserialize(MapAccessDeserializer::new(map))?;
                match m.remaining_fields.into_iter().next() {
                    Some((name, Value::Null)) => Ok(NamedRulesetConfig { name, cfg: m.cfg }),
                    Some((name, _)) => Err(Error::custom(format!("invalid configuration for ruleset \"{}\" (check if it is indented under the ruleset name)", name))),
                    _ => Err(Error::custom("expected a ruleset configuration")),
                }
            }
        }

        deserializer.deserialize_any(StringOrStruct {})
    }
}

impl Serialize for NamedRulesetConfig {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if self.cfg == RulesetConfig::default() {
            self.name.serialize(serializer)
        } else {
            #[derive(Serialize)]
            #[serde(untagged)]
            enum CfgMapValue<'a> {
                Null,
                Rules(&'a IndexMap<String, RuleConfig>),
                Paths(&'a Vec<PathPattern>),
            }

            let mut map = IndexMap::new();
            map.insert(self.name.as_str(), CfgMapValue::Null);
            if !self.cfg.paths.ignore.is_empty() {
                map.insert("ignore", CfgMapValue::Paths(&self.cfg.paths.ignore));
            }
            if let Some(only) = &self.cfg.paths.only {
                map.insert("only", CfgMapValue::Paths(only));
            }
            if !self.cfg.rules.is_empty() {
                map.insert("rules", CfgMapValue::Rules(&self.cfg.rules));
            }
            map.serialize(serializer)
        }
    }
}

/// Deserializer for a `RuleConfig` map which rejects duplicate rules.
pub fn deserialize_rule_configs<'de, D>(
    deserializer: D,
) -> Result<IndexMap<String, RuleConfig>, D::Error>
where
    D: Deserializer<'de>,
{
    struct RuleConfigVisitor {}
    impl<'de> Visitor<'de> for RuleConfigVisitor {
        type Value = IndexMap<String, RuleConfig>;

        fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
            formatter.write_str("an optional map from string to rule configuration")
        }

        /// Deserializes a map of string to `RuleConfig`.
        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            let mut out = IndexMap::new();
            while let Some((k, v)) = map.next_entry::<String, RuleConfig>()? {
                if out.insert(k.clone(), v).is_some() {
                    return Err(Error::custom(format!("found duplicate rule: {}", k)));
                }
            }
            Ok(out)
        }
    }
    deserializer.deserialize_any(RuleConfigVisitor {})
}

/// Deserializer for argument values:
/// ```yaml
/// arguments:
///   foo: abc
///   bar: 1234
///   baz:
///     /: abc
///     uno/dos: 1234
/// ```
impl<'de> Deserialize<'de> for ArgumentValues {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum AnyToString {
            Bool(bool),
            I64(i64),
            U64(u64),
            I128(i128),
            U128(u128),
            F64(f64),
            Str(String),
        }

        impl Display for AnyToString {
            fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
                match self {
                    AnyToString::Bool(v) => f.write_fmt(format_args!("{}", v)),
                    AnyToString::I64(v) => f.write_fmt(format_args!("{}", v)),
                    AnyToString::U64(v) => f.write_fmt(format_args!("{}", v)),
                    AnyToString::I128(v) => f.write_fmt(format_args!("{}", v)),
                    AnyToString::U128(v) => f.write_fmt(format_args!("{}", v)),
                    AnyToString::F64(v) => f.write_fmt(format_args!("{}", v)),
                    AnyToString::Str(v) => f.write_str(v),
                }
            }
        }

        #[derive(Deserialize)]
        #[serde(untagged)]
        enum StringOrMap {
            Str(AnyToString),
            Map(IndexMap<String, AnyToString>),
        }

        match StringOrMap::deserialize(deserializer) {
            Err(_) => Err(Error::custom(
                "expected a string or a map from path to string",
            )),
            Ok(StringOrMap::Str(s)) => Ok(ArgumentValues {
                by_subtree: IndexMap::from([("".to_string(), s.to_string())]),
            }),
            Ok(StringOrMap::Map(m)) => Ok(ArgumentValues {
                by_subtree: m
                    .into_iter()
                    .map(|(k, v)| {
                        if k == "/" || k == "**" {
                            ("".to_string(), v.to_string())
                        } else {
                            (k, v.to_string())
                        }
                    })
                    .collect(),
            }),
        }
    }
}

impl Serialize for ArgumentValues {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if let (1, Some(val)) = (self.by_subtree.len(), self.by_subtree.get("")) {
            val.serialize(serializer)
        } else {
            self.by_subtree
                .iter()
                .map(|(k, v)| {
                    if k.is_empty() {
                        ("/", v.as_str())
                    } else {
                        (k.as_str(), v.as_str())
                    }
                })
                .collect::<IndexMap<_, _>>()
                .serialize(serializer)
        }
    }
}

/// Deserializer for a `RuleCategory` which rejects the 'unknown' option.
pub fn deserialize_category<'de, D>(deserializer: D) -> Result<Option<RuleCategory>, D::Error>
where
    D: Deserializer<'de>,
{
    let category = RuleCategory::deserialize(deserializer)?;
    if category == RuleCategory::Unknown {
        Err(Error::invalid_value(
            Unexpected::Str("unknown"),
            &"a rule category",
        ))
    } else {
        Ok(Some(category))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::config_file::{
        ArgumentValues, ConfigFile, PathConfig, PathPattern, RuleConfig, RulesetConfig,
    };
    use std::fs;
    use std::path::{Path, PathBuf};

    // Location of the configuration file examples that accompany the schema.
    const CFG_FILE_EXAMPLES_DIR: &str = "../../schema/examples";

    // Returns pairs of (path, content) of the example files in the given subdirectory.
    fn get_example_configs(suffix: &str) -> impl Iterator<Item = (PathBuf, String)> {
        let dir_path = Path::new(CFG_FILE_EXAMPLES_DIR).join(suffix);
        let entries = fs::read_dir(dir_path).expect("could not read the examples directory");
        entries
            .map(|e| e.expect("could not find an example entry").path())
            .filter(|path| path.is_file())
            .map(|path| {
                let cfg = fs::read_to_string(&path).expect("could not open example");
                (path, cfg)
            })
    }

    // 'Valid' examples are indeed valid according to this parser.
    #[test]
    fn test_valid_examples_can_be_parsed() {
        for (path, cfg) in get_example_configs("valid") {
            let result = parse_config_file(&cfg);
            assert!(
                result.is_ok(),
                "expected a valid configuration in {}: {}",
                path.display(),
                result.err().unwrap()
            );
        }
    }

    // 'Invalid' examples are indeed invalid according to this parser.
    #[test]
    fn test_invalid_examples_cannot_be_parsed() {
        for (path, cfg) in get_example_configs("invalid") {
            let result = parse_config_file(&cfg);
            assert!(
                result.is_err(),
                "expected an invalid configuration in {}",
                path.display()
            );
        }
    }

    // `rulesets` parsed as a list of ruleset names
    #[test]
    fn test_parse_rulesets_as_list_of_strings() {
        let data = r#"
rulesets:
  - python-security
  - go-best-practices
    "#;
        let expected = ConfigFile {
            schema_version: "v1".to_string(),
            rulesets: IndexMap::from([
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
    fn test_cannot_parse_rulesets_as_map() {
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

        let res = parse_config_file(data);
        assert!(res.is_err());
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
            schema_version: "v1".to_string(),
            rulesets: IndexMap::from([
                ("c-best-practices".to_string(), RulesetConfig::default()),
                ("rust-best-practices".to_string(), RulesetConfig::default()),
                (
                    "go-best-practices".to_string(),
                    RulesetConfig {
                        paths: PathConfig {
                            only: Some(vec!["foo".to_string().into()]),
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
                            ignore: vec!["bar".to_string().into()],
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

    // Parse improperly formatted YAML where the rulesets are lists of maps
    // or mixed lists of strings and maps.
    #[test]
    fn test_cannot_parse_rulesets_with_bad_indentation() {
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

        let res = parse_config_file(data);
        assert!(res.is_err());
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
  - python-security:
    rules:
      no-eval:
        only:
          - "py/**"
        ignore:
          - "py/insecure/**"
    "#;
        let expected = ConfigFile {
            schema_version: "v1".to_string(),
            rulesets: IndexMap::from([(
                "python-security".to_string(),
                RulesetConfig {
                    paths: PathConfig::default(),
                    rules: IndexMap::from([(
                        "no-eval".to_string(),
                        RuleConfig {
                            paths: PathConfig {
                                only: Some(vec!["py/**".to_string().into()]),
                                ignore: vec!["py/insecure/**".to_string().into()],
                            },
                            arguments: IndexMap::new(),
                            severity: None,
                            category: None,
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

    // Argument values
    #[test]
    fn test_parse_argument_values() {
        let data = r#"
rulesets:
  - python-security:
    rules:
      no-eval:
        arguments:
          arg1: 100
          arg2:
            /: 200
            uno: 201
            uno/dos: 202
            tres: 203
      yes-eval:
        arguments:
          arg3: 300
          arg4:
            cuatro: 400
        "#;

        let expected = ConfigFile {
            schema_version: "v1".to_string(),
            rulesets: IndexMap::from([(
                "python-security".to_string(),
                RulesetConfig {
                    paths: PathConfig::default(),
                    rules: IndexMap::from([
                        (
                            "no-eval".to_string(),
                            RuleConfig {
                                paths: PathConfig::default(),
                                arguments: IndexMap::from([
                                    (
                                        "arg1".to_string(),
                                        ArgumentValues {
                                            by_subtree: IndexMap::from([(
                                                "".to_string(),
                                                "100".to_string(),
                                            )]),
                                        },
                                    ),
                                    (
                                        "arg2".to_string(),
                                        ArgumentValues {
                                            by_subtree: IndexMap::from([
                                                ("".to_string(), "200".to_string()),
                                                ("uno".to_string(), "201".to_string()),
                                                ("uno/dos".to_string(), "202".to_string()),
                                                ("tres".to_string(), "203".to_string()),
                                            ]),
                                        },
                                    ),
                                ]),
                                severity: None,
                                category: None,
                            },
                        ),
                        (
                            "yes-eval".to_string(),
                            RuleConfig {
                                paths: PathConfig::default(),
                                arguments: IndexMap::from([
                                    (
                                        "arg3".to_string(),
                                        ArgumentValues {
                                            by_subtree: IndexMap::from([(
                                                "".to_string(),
                                                "300".to_string(),
                                            )]),
                                        },
                                    ),
                                    (
                                        "arg4".to_string(),
                                        ArgumentValues {
                                            by_subtree: IndexMap::from([(
                                                "cuatro".to_string(),
                                                "400".to_string(),
                                            )]),
                                        },
                                    ),
                                ]),
                                severity: None,
                                category: None,
                            },
                        ),
                    ]),
                },
            )]),
            ..ConfigFile::default()
        };
        let res = parse_config_file(data);
        assert_eq!(expected, res.unwrap());
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
            schema_version: "v1".to_string(),
            rulesets: IndexMap::from([("python-security".to_string(), RulesetConfig::default())]),
            paths: PathConfig {
                only: Some(vec!["py/**/foo/*.py".to_string().into()]),
                ignore: vec![
                    "py/testing/*.py".to_string().into(),
                    "**/test/**".to_string().into(),
                    "path1".to_string().into(),
                ],
            },
            ignore_gitignore: Some(false),
            max_file_size_kb: Some(512),
            ignore_generated_files: None,
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

    #[test]
    fn test_serialize_ruleset_configs_empty() {
        let config = ConfigFile {
            schema_version: "v1".to_string(),
            rulesets: IndexMap::new(),
            ..Default::default()
        };

        let serialized = config_file_to_yaml(&config).unwrap();
        assert_eq!(
            serialized.trim(),
            r#"schema-version: v1
rulesets: []"#
        );
    }

    #[test]
    fn test_serialize_ruleset_configs_single_empty() {
        let mut rulesets = IndexMap::new();
        rulesets.insert("java-1".to_string(), RulesetConfig::default());

        let config = ConfigFile {
            schema_version: "v1".to_string(),
            rulesets,
            ..Default::default()
        };

        let serialized = config_file_to_yaml(&config).unwrap();
        assert_eq!(
            serialized.trim(),
            r#"schema-version: v1
rulesets:
- java-1"#
        );
    }

    #[test]
    fn test_serialize_ruleset_configs_multiple() {
        let mut rulesets = IndexMap::new();
        rulesets.insert("java-1".to_string(), RulesetConfig::default());

        let mut rules = IndexMap::new();
        rules.insert(
            "rule-number-1".into(),
            RuleConfig {
                paths: PathConfig {
                    ignore: vec![PathPattern {
                        glob: None,
                        prefix: "ignore/to/win".into(),
                    }],
                    only: None,
                },
                ..Default::default()
            },
        );

        rulesets.insert(
            "java-security".to_string(),
            RulesetConfig {
                // Fill in with test data...
                rules,
                paths: PathConfig {
                    ignore: vec![],
                    only: Some(vec![PathPattern {
                        glob: None,
                        prefix: "my-path/to/heaven".into(),
                    }]),
                },
            },
        );

        let config = ConfigFile {
            schema_version: "v1".to_string(),
            rulesets,
            ..Default::default()
        };

        let serialized = config_file_to_yaml(&config).unwrap();
        let serialized = serialized.trim();
        let expected = r#"
schema-version: v1
rulesets:
- java-1
- java-security: null
  only:
  - my-path/to/heaven
  rules:
    rule-number-1:
      ignore:
      - ignore/to/win
      "#
        .trim();

        assert_eq!(serialized, expected);
    }

    #[test]
    fn test_serialize_ruleset_configs_multiple_order_is_not_affected() {
        let mut rulesets = IndexMap::new();
        rulesets.insert("java-1".to_string(), RulesetConfig::default());

        let mut rules = IndexMap::new();
        rules.insert(
            "rule-number-1".into(),
            RuleConfig {
                paths: PathConfig {
                    ignore: vec![PathPattern {
                        glob: None,
                        prefix: "ignore/to/win".into(),
                    }],
                    only: None,
                },
                ..Default::default()
            },
        );

        rulesets.insert(
            "rule-security".to_string(),
            RulesetConfig {
                // Fill in with test data...
                rules,
                paths: PathConfig {
                    ignore: vec![],
                    only: Some(vec![PathPattern {
                        glob: None,
                        prefix: "my-path/to/heaven".into(),
                    }]),
                },
            },
        );

        let config = ConfigFile {
            schema_version: "v1".to_string(),
            rulesets,
            ..Default::default()
        };

        let serialized = config_file_to_yaml(&config).unwrap();
        let serialized = serialized.trim();
        let expected = r#"
schema-version: v1
rulesets:
- java-1
- rule-security: null
  only:
  - my-path/to/heaven
  rules:
    rule-number-1:
      ignore:
      - ignore/to/win
      "#
        .trim();

        assert_eq!(serialized, expected);
    }

    #[test]
    fn test_serialize_arguments() {
        let mut rulesets = IndexMap::new();

        let mut rules: IndexMap<String, RuleConfig> = IndexMap::new();
        let mut arguments = IndexMap::new();
        let mut by_subtree = IndexMap::new();
        by_subtree.insert("".to_string(), "3".to_string());
        arguments.insert("max-params".to_string(), ArgumentValues { by_subtree });

        rules.insert(
            "rule-number-1".into(),
            RuleConfig {
                arguments,
                ..Default::default()
            },
        );

        rulesets.insert(
            "java-1".to_string(),
            RulesetConfig {
                rules,
                ..Default::default()
            },
        );

        let config = ConfigFile {
            schema_version: "v1".to_string(),
            rulesets,
            ..Default::default()
        };

        let serialized = config_file_to_yaml(&config).unwrap();
        let serialized = serialized.trim();
        let expected = r"
schema-version: v1
rulesets:
- java-1: null
  rules:
    rule-number-1:
      arguments:
        max-params: '3'
"
        .trim();

        assert_eq!(serialized, expected);
    }

    #[test]
    fn test_serialize_arguments_multiple_subtrees() {
        let mut rulesets = IndexMap::new();

        let mut rules: IndexMap<String, RuleConfig> = IndexMap::new();
        let mut arguments = IndexMap::new();
        let mut by_subtree = IndexMap::new();
        by_subtree.insert("".to_string(), "3".to_string());
        by_subtree.insert("my-path/to-file".to_string(), "4".to_string());
        arguments.insert("max-params".to_string(), ArgumentValues { by_subtree });

        rules.insert(
            "rule-number-1".into(),
            RuleConfig {
                arguments,
                ..Default::default()
            },
        );

        rulesets.insert(
            "java-1".to_string(),
            RulesetConfig {
                rules,
                ..Default::default()
            },
        );

        let config = ConfigFile {
            schema_version: "v1".to_string(),
            rulesets,
            ..Default::default()
        };

        let serialized = config_file_to_yaml(&config).unwrap();
        let serialized = serialized.trim();
        let expected = r"
schema-version: v1
rulesets:
- java-1: null
  rules:
    rule-number-1:
      arguments:
        max-params:
          /: '3'
          my-path/to-file: '4'
"
        .trim();

        assert_eq!(serialized, expected);
    }
}
