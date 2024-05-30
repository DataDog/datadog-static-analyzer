use anyhow::Result;
use indexmap::IndexMap;
use serde::de::value::MapAccessDeserializer;
use serde::de::{Error, MapAccess, Unexpected, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_yaml::Value;
use std::collections::HashSet;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::marker::PhantomData;

use crate::model::config_file::{
    join_path, split_path, BySubtree, ConfigFile, PathConfig, PathPattern, RuleConfig,
    RulesetConfig,
};
use crate::model::rule::{RuleCategory, RuleSeverity};

pub fn parse_config_file(config_contents: &str) -> Result<ConfigFile> {
    let yaml_config: YamlConfigFile = serde_yaml::from_str(config_contents)?;
    Ok(yaml_config.into())
}

pub fn config_file_to_yaml(cfg: &ConfigFile) -> Result<String> {
    let yaml_config: YamlConfigFile = cfg.clone().into();
    Ok(serde_yaml::to_string(&yaml_config)?)
}

// YAML-serializable configuration file.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct YamlConfigFile {
    #[serde(default)]
    schema_version: YamlSchemaVersion,
    rulesets: YamlRulesetList,
    #[serde(flatten)]
    paths: YamlPathConfig,
    #[serde(skip_serializing_if = "Option::is_none")]
    ignore_paths: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ignore_gitignore: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_file_size_kb: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ignore_generated_files: Option<bool>,
}

impl From<YamlConfigFile> for ConfigFile {
    fn from(value: YamlConfigFile) -> Self {
        ConfigFile {
            rulesets: value.rulesets.into(),
            paths: {
                let mut paths: PathConfig = value.paths.into();
                if let Some(ignore) = value.ignore_paths {
                    paths
                        .ignore
                        .extend(ignore.into_iter().map(PathPattern::from));
                }
                paths
            },
            ignore_gitignore: value.ignore_gitignore,
            max_file_size_kb: value.max_file_size_kb,
            ignore_generated_files: value.ignore_generated_files,
        }
    }
}

impl From<ConfigFile> for YamlConfigFile {
    fn from(value: ConfigFile) -> Self {
        YamlConfigFile {
            schema_version: YamlSchemaVersion::V1,
            rulesets: value.rulesets.into(),
            paths: value.paths.into(),
            ignore_paths: None,
            ignore_gitignore: value.ignore_gitignore,
            max_file_size_kb: value.max_file_size_kb,
            ignore_generated_files: value.ignore_generated_files,
        }
    }
}

// YAML-serializable schema version.
// It only contains the expected value for this parser.
#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
enum YamlSchemaVersion {
    #[default]
    V1,
}

// YAML-serializable ruleset list.
// When deserializing, disallows two rulesets with the same name.
#[derive(Serialize)]
#[serde(transparent)]
struct YamlRulesetList(Vec<YamlNamedRulesetConfig>);

impl<'de> Deserialize<'de> for YamlRulesetList {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let list = Vec::<YamlNamedRulesetConfig>::deserialize(deserializer)?;
        if list.is_empty() {
            return Err(Error::custom("no rulesets were specified"));
        }
        let mut names = HashSet::new();
        for item in &list {
            if !names.insert(&item.name) {
                return Err(Error::custom(format!("duplicate ruleset: {}", item.name)));
            }
        }
        Ok(YamlRulesetList(list))
    }
}

impl From<YamlRulesetList> for IndexMap<String, RulesetConfig> {
    fn from(value: YamlRulesetList) -> Self {
        value
            .0
            .into_iter()
            .map(|v| (v.name, v.cfg.into()))
            .collect()
    }
}

impl From<IndexMap<String, RulesetConfig>> for YamlRulesetList {
    fn from(value: IndexMap<String, RulesetConfig>) -> Self {
        YamlRulesetList(
            value
                .into_iter()
                .map(|(name, cfg)| YamlNamedRulesetConfig {
                    name,
                    cfg: cfg.into(),
                })
                .collect(),
        )
    }
}

// YAML-serializable ruleset configuration, including a name.
// With a default configuration, this serializes and deserialized to only the ruleset name;
// otherwise, to a map whose first element has the ruleset name as the key and a null value.
struct YamlNamedRulesetConfig {
    name: String,
    cfg: YamlRulesetConfig,
}

impl<'de> Deserialize<'de> for YamlNamedRulesetConfig {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StringOrStruct {}
        impl<'de> Visitor<'de> for StringOrStruct {
            type Value = YamlNamedRulesetConfig;
            fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                formatter.write_str("a string or a ruleset configuration")
            }
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                Ok(YamlNamedRulesetConfig {
                    name: v.to_string(),
                    cfg: YamlRulesetConfig::default(),
                })
            }
            fn visit_map<A>(self, map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                #[derive(Deserialize)]
                struct Holder {
                    #[serde(flatten)]
                    cfg: YamlRulesetConfig,
                    #[serde(flatten)]
                    #[serde(default)]
                    remaining_fields: IndexMap<String, Value>,
                }
                let m = Holder::deserialize(MapAccessDeserializer::new(map))?;
                match m.remaining_fields.into_iter().next() {
                    Some((name, Value::Null)) => Ok(YamlNamedRulesetConfig { name, cfg: m.cfg }),
                    Some((name, _)) => Err(Error::custom(format!("invalid configuration for ruleset \"{}\" (check if it is indented under the ruleset name)", name))),
                    _ => Err(Error::custom("expected a ruleset configuration")),
                }
            }
        }

        deserializer.deserialize_any(StringOrStruct {})
    }
}

impl Serialize for YamlNamedRulesetConfig {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if self.cfg == YamlRulesetConfig::default() {
            self.name.serialize(serializer)
        } else {
            #[derive(Serialize)]
            struct Holder<'a> {
                #[serde(flatten)]
                name: IndexMap<&'a str, ()>,
                #[serde(flatten)]
                cfg: &'a YamlRulesetConfig,
            }
            Holder {
                name: IndexMap::from([(self.name.as_str(), ())]),
                cfg: &self.cfg,
            }
            .serialize(serializer)
        }
    }
}

// YAML-serializable ruleset configuration, without the name.
#[derive(Deserialize, Serialize, Default, PartialEq)]
struct YamlRulesetConfig {
    #[serde(flatten)]
    paths: YamlPathConfig,
    #[serde(default, skip_serializing_if = "UniqueKeyMap::is_empty")]
    rules: UniqueKeyMap<YamlRuleConfig>,
}

impl From<YamlRulesetConfig> for RulesetConfig {
    fn from(value: YamlRulesetConfig) -> Self {
        RulesetConfig {
            paths: value.paths.into(),
            rules: value
                .rules
                .0
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
        }
    }
}

impl From<RulesetConfig> for YamlRulesetConfig {
    fn from(value: RulesetConfig) -> Self {
        YamlRulesetConfig {
            paths: value.paths.into(),
            rules: UniqueKeyMap(
                value
                    .rules
                    .into_iter()
                    .map(|(k, v)| (k, v.into()))
                    .collect(),
            ),
        }
    }
}

// YAML-serializable by-path-or-glob include/exclude configuration.
#[derive(Deserialize, Serialize, Default, PartialEq)]
struct YamlPathConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    only: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    ignore: Vec<String>,
}

impl From<YamlPathConfig> for PathConfig {
    fn from(value: YamlPathConfig) -> Self {
        PathConfig {
            only: value
                .only
                .map(|only| only.into_iter().map(PathPattern::from).collect()),
            ignore: value.ignore.into_iter().map(PathPattern::from).collect(),
        }
    }
}

impl From<PathConfig> for YamlPathConfig {
    fn from(value: PathConfig) -> Self {
        YamlPathConfig {
            only: value
                .only
                .map(|only| only.into_iter().map(String::from).collect()),
            ignore: value.ignore.into_iter().map(String::from).collect(),
        }
    }
}

// YAML-serializeable rule configuration.
#[derive(Deserialize, Serialize, Default, PartialEq)]
struct YamlRuleConfig {
    #[serde(flatten)]
    paths: YamlPathConfig,
    #[serde(default, skip_serializing_if = "UniqueKeyMap::is_empty")]
    arguments: UniqueKeyMap<YamlArgumentValues>,
    #[serde(skip_serializing_if = "Option::is_none")]
    severity: Option<RuleSeverity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    category: Option<YamlRuleCategory>,
}

impl From<YamlRuleConfig> for RuleConfig {
    fn from(value: YamlRuleConfig) -> Self {
        RuleConfig {
            paths: value.paths.into(),
            arguments: value
                .arguments
                .0
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
            severity: value.severity,
            category: value.category.map(|c| c.0),
        }
    }
}

impl From<RuleConfig> for YamlRuleConfig {
    fn from(value: RuleConfig) -> Self {
        YamlRuleConfig {
            paths: value.paths.into(),
            arguments: UniqueKeyMap(
                value
                    .arguments
                    .into_iter()
                    .map(|(k, v)| (k, v.into()))
                    .collect(),
            ),
            severity: value.severity,
            category: value.category.map(YamlRuleCategory),
        }
    }
}

// YAML-serializable argument value map.
// If it only contains one value for the root directory, it serializes and deserializes as
// a string; otherwise, as a map from path prefix to value.
#[derive(Default, PartialEq)]
struct YamlArgumentValues(IndexMap<String, String>);

impl<'de> Deserialize<'de> for YamlArgumentValues {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Holder {
            Single(AnyAsString),
            ByPath(UniqueKeyMap<AnyAsString>),
        }
        let values = match Holder::deserialize(deserializer)? {
            Holder::Single(v) => IndexMap::from([("".to_string(), v.to_string())]),
            Holder::ByPath(m) => {
                m.0.into_iter()
                    .map(|(k, v)| {
                        if k == "/" || k == "**" {
                            ("".to_string(), v.to_string())
                        } else {
                            (k, v.to_string())
                        }
                    })
                    .collect()
            }
        };
        Ok(YamlArgumentValues(values))
    }
}

impl Serialize for YamlArgumentValues {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if let (1, Some(value)) = (self.0.len(), self.0.get("")) {
            value.serialize(serializer)
        } else {
            self.0
                .iter()
                .map(|(k, v)| {
                    if k.is_empty() {
                        ("/", v)
                    } else {
                        (k.as_str(), v)
                    }
                })
                .collect::<IndexMap<_, _>>()
                .serialize(serializer)
        }
    }
}

impl From<YamlArgumentValues> for BySubtree<String> {
    fn from(value: YamlArgumentValues) -> Self {
        let mut out = BySubtree::new();
        for (k, v) in value.0 {
            out.insert(&split_path(k), v);
        }
        out
    }
}

impl From<BySubtree<String>> for YamlArgumentValues {
    fn from(value: BySubtree<String>) -> Self {
        YamlArgumentValues(
            value
                .iter()
                .map(|(k, v)| (join_path(&k.into_iter().cloned().collect()), v.clone()))
                .collect(),
        )
    }
}

// YAML-serializable rule category. The 'unknown' value is disallowed when deserializing.
#[derive(Serialize, PartialEq)]
#[serde(transparent)]
struct YamlRuleCategory(RuleCategory);

impl<'de> Deserialize<'de> for YamlRuleCategory {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
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
            Ok(YamlRuleCategory(category))
        }
    }
}

// A map from string to value that disallows repeated keys when deserializing.
#[derive(Serialize, Default, PartialEq)]
#[serde(transparent)]
struct UniqueKeyMap<V>(IndexMap<String, V>);

impl<V> UniqueKeyMap<V> {
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<'de, V> Deserialize<'de> for UniqueKeyMap<V>
where
    V: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct UniqueKeyVisitor<U>(PhantomData<fn() -> U>);
        impl<'de, U> Visitor<'de> for UniqueKeyVisitor<U>
        where
            U: Deserialize<'de>,
        {
            type Value = IndexMap<String, U>;
            fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                formatter.write_str("a map with unique keys")
            }
            fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut out = IndexMap::new();
                while let Some((k, v)) = map.next_entry()? {
                    if let (i, Some(_)) = out.insert_full(k, v) {
                        return Err(Error::custom(format!(
                            "duplicate map key: {}",
                            out.get_index(i).unwrap().0
                        )));
                    }
                }
                Ok(out)
            }
        }
        Ok(UniqueKeyMap(
            deserializer.deserialize_any(UniqueKeyVisitor(PhantomData))?,
        ))
    }
}

// A value that, when deserializing, is cast to a string.
#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum AnyAsString {
    Bool(bool),
    I64(i64),
    U64(u64),
    I128(i128),
    U128(u128),
    F64(f64),
    Str(String),
}

impl Display for AnyAsString {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            AnyAsString::Bool(v) => f.write_fmt(format_args!("{}", v)),
            AnyAsString::I64(v) => f.write_fmt(format_args!("{}", v)),
            AnyAsString::U64(v) => f.write_fmt(format_args!("{}", v)),
            AnyAsString::I128(v) => f.write_fmt(format_args!("{}", v)),
            AnyAsString::U128(v) => f.write_fmt(format_args!("{}", v)),
            AnyAsString::F64(v) => f.write_fmt(format_args!("{}", v)),
            AnyAsString::Str(v) => f.write_str(v),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::config_file::{
        values_by_subtree, ConfigFile, PathConfig, PathPattern, RuleConfig, RulesetConfig,
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
                                        values_by_subtree([("", "100".to_string())]),
                                    ),
                                    (
                                        "arg2".to_string(),
                                        values_by_subtree([
                                            ("", "200".to_string()),
                                            ("uno", "201".to_string()),
                                            ("uno/dos", "202".to_string()),
                                            ("tres", "203".to_string()),
                                        ]),
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
                                        values_by_subtree([("", "300".to_string())]),
                                    ),
                                    (
                                        "arg4".to_string(),
                                        values_by_subtree([("cuatro", "400".to_string())]),
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
        arguments.insert(
            "max-params".to_string(),
            values_by_subtree([("", "3".to_string())]),
        );

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
        arguments.insert(
            "max-params".to_string(),
            values_by_subtree([("", "3".to_string()), ("my-path/to-file", "4".to_string())]),
        );

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
