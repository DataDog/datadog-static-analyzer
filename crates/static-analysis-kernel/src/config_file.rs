use crate::model::config_file::{
    BySubtree, ConfigFile, PathConfig, RuleConfig, RulesetConfig, SplitPath,
};
use crate::model::rule::{RuleCategory, RuleSeverity};
use anyhow::Result;
use indexmap::IndexMap;
use serde::de::value::MapAccessDeserializer;
use serde::de::{Error, MapAccess, Unexpected, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_yaml::Value;
use std::collections::HashSet;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::hash::Hash;
use std::marker::PhantomData;

// Parses the provided YAML text, returning a ConfigFile.
pub fn parse_config_file(config_contents: &str) -> Result<ConfigFile> {
    let yaml_config: YamlConfigFile = serde_yaml::from_str(config_contents)?;
    Ok(yaml_config.into())
}

// Generates a YAML for the provided ConfigFile.
pub fn config_file_to_yaml(config: &ConfigFile) -> Result<String> {
    let yaml_config: YamlConfigFile = config.clone().into();
    Ok(serde_yaml::to_string(&yaml_config)?)
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
struct YamlConfigFile {
    #[serde(default)]
    schema_version: SchemaVersion,
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

// A marker for the schema version.
// No content because it's only deserialized if the schema version is correct.
#[derive(Default)]
struct SchemaVersion {}

// A list of configured rulesets. When deserialized, it gives an error if a ruleset is duplicated.
struct YamlRulesetList(Vec<NamedRulesetConfig>);

// A ruleset name with its configuration. It can be deserialized as a single string (populating
// the name only) or as a map (populating the name and configuration in a special way.)
struct NamedRulesetConfig {
    name: String,
    cfg: YamlRulesetConfig,
}

// A ruleset configuration.
#[derive(Deserialize, Serialize, Default, PartialEq)]
struct YamlRulesetConfig {
    #[serde(flatten)]
    pub paths: YamlPathConfig,
    #[serde(default)]
    pub rules: UniqueKeyMap<String, YamlRuleConfig>,
}

// An 'only'/'ignore' configuration.
#[derive(Deserialize, Serialize, Default, PartialEq)]
pub struct YamlPathConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub only: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ignore: Vec<String>,
}

// A configuration for a rule.
#[derive(Deserialize, Serialize, Default, PartialEq)]
struct YamlRuleConfig {
    #[serde(flatten)]
    pub paths: YamlPathConfig,
    #[serde(default, skip_serializing_if = "UniqueKeyMap::is_empty")]
    pub arguments: UniqueKeyMap<String, YamlBySubtree<AnyAsString>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<RuleSeverity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<YamlRuleCategory>,
}

// An object that can hold several values that depend on a subtree prefix.
#[derive(Default, PartialEq)]
struct YamlBySubtree<T>(IndexMap<String, T>);

// A restricted version of RuleCategory, which doesn't deserialize the 'unknown' value.
#[derive(Serialize, PartialEq)]
struct YamlRuleCategory {
    #[serde(flatten)]
    category: RuleCategory,
}

// A holder for a value of any primitive type that will be interpreted as a string.
#[derive(Serialize, Deserialize, PartialEq)]
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

// A map that, when deserialized, gives an error if a key is duplicated.
#[derive(Default, PartialEq)]
struct UniqueKeyMap<K, V>(IndexMap<K, V>)
where
    K: Hash + Eq;

impl<K, V> UniqueKeyMap<K, V>
where
    K: Hash + Eq,
{
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

const SCHEMA_VERSION: &str = "v1";

// Deserializer for the schema version.
// It requires the field to contain the SCHEMA_VERSION string and returns a marker if so.
impl<'de> Deserialize<'de> for SchemaVersion {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match String::deserialize(deserializer)?.as_str() {
            SCHEMA_VERSION => Ok(SchemaVersion {}),
            v => Err(Error::invalid_value(
                Unexpected::Str(v),
                &format!("\"{}\"", SCHEMA_VERSION).as_str(),
            )),
        }
    }
}

// Serializer for the schema version. Outputs the SCHEMA_VERSION string.
impl Serialize for SchemaVersion {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        SCHEMA_VERSION.serialize(serializer)
    }
}

// Deserializer for a ruleset list.
impl<'de> Deserialize<'de> for YamlRulesetList {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut names = HashSet::new();
        let list = Vec::<NamedRulesetConfig>::deserialize(deserializer)?;
        if list.is_empty() {
            return Err(Error::custom("no rulesets were specified"));
        }
        for nrc in &list {
            if !names.insert(nrc.name.clone()) {
                return Err(Error::custom(format!("duplicate ruleset: {}", nrc.name)));
            }
        }
        Ok(YamlRulesetList(list))
    }
}

impl Serialize for YamlRulesetList {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

// Deserializer for a (named) ruleset config. It takes either a string (signifying a ruleset with
// a default configuration) or a map whose first key is the name and the remaining items are the
// ruleset configuration.
impl<'de> Deserialize<'de> for NamedRulesetConfig {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
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
                    Some((name, Value::Null)) => Ok(NamedRulesetConfig { name, cfg: m.cfg }),
                    Some((name, _)) => Err(Error::custom(format!("invalid configuration for ruleset \"{}\" (check if it is indented under the ruleset name)", name))),
                    _ => Err(Error::custom("expected a ruleset configuration")),
                }
            }
        }

        deserializer.deserialize_any(StringOrStruct {})
    }
}

// Serializer for a (named) ruleset configuration. If the ruleset configuration is the default,
// it outputs just the name.
impl Serialize for NamedRulesetConfig {
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

            let out = Holder {
                name: IndexMap::from([(self.name.as_str(), ())]),
                cfg: &self.cfg,
            };
            out.serialize(serializer)
        }
    }
}

// Deserializer for a value that can vary depending on the subtree. It takes either a single value,
// which takes effect everywhere, or a map from a path prefix to the value that will take effect
// within that path prefix.
impl<'de, T> Deserialize<'de> for YamlBySubtree<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Holder<V> {
            Single(V),
            Map(UniqueKeyMap<String, V>),
        }
        match Holder::<T>::deserialize(deserializer)? {
            Holder::Single(value) => Ok(YamlBySubtree(IndexMap::from([("".to_string(), value)]))),
            Holder::Map(map) => Ok(YamlBySubtree(map.0)),
        }
    }
}

// Serializer for a value that can vary depending on the subtree. If the map only contains a global
// value, it is serialized as the value itself; otherwise, it is serialized as a map.
impl<T> Serialize for YamlBySubtree<T>
where
    T: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if let (1, Some(value)) = (self.0.len(), self.0.get("/")) {
            value.serialize(serializer)
        } else {
            self.0.serialize(serializer)
        }
    }
}

// A deserializer for a RuleCategory that rejects the "unknown" category.
impl<'de> Deserialize<'de> for YamlRuleCategory {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match RuleCategory::deserialize(deserializer)? {
            RuleCategory::Unknown => Err(Error::invalid_value(
                Unexpected::Str("unknown"),
                &"a rule category",
            )),
            category => Ok(YamlRuleCategory { category }),
        }
    }
}

// A deserializer for a UniqueKeyMap that rejects the input when a key appears twice.
impl<'de, K, V> Deserialize<'de> for UniqueKeyMap<K, V>
where
    K: Deserialize<'de> + Hash + Eq + Display,
    V: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct UniqueKeyMapVisitor<Q, U>(PhantomData<fn() -> (Q, U)>);
        impl<'de, Q, U> Visitor<'de> for UniqueKeyMapVisitor<Q, U>
        where
            Q: Deserialize<'de> + Hash + Eq + Display,
            U: Deserialize<'de>,
        {
            type Value = UniqueKeyMap<Q, U>;

            fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                formatter.write_str("a map with unique keys")
            }

            fn visit_map<A>(self, mut map_access: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut map = IndexMap::new();
                while let Some((key, value)) = map_access.next_entry::<Q, U>()? {
                    if let (i, Some(_)) = map.insert_full(key, value) {
                        return Err(Error::custom(format!(
                            "found a duplicate key '{}'",
                            map.get_index(i).unwrap().0
                        )));
                    }
                }
                Ok(UniqueKeyMap(map))
            }
        }
        deserializer.deserialize_any(UniqueKeyMapVisitor(PhantomData))
    }
}

// Serializer for UniqueKeyMap; nothing special.
impl<K, V> Serialize for UniqueKeyMap<K, V>
where
    K: Serialize + Hash + Eq,
    V: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl From<YamlConfigFile> for ConfigFile {
    fn from(value: YamlConfigFile) -> Self {
        ConfigFile {
            rulesets: value.rulesets.into(),
            paths: {
                let mut paths = value.paths;
                if let Some(ip) = value.ignore_paths {
                    paths.ignore.extend(ip);
                }
                paths.into()
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
            schema_version: SchemaVersion {},
            rulesets: value.rulesets.into(),
            paths: value.paths.into(),
            ignore_paths: None,
            ignore_gitignore: value.ignore_gitignore,
            max_file_size_kb: value.max_file_size_kb,
            ignore_generated_files: value.ignore_generated_files,
        }
    }
}

impl From<YamlPathConfig> for PathConfig {
    fn from(value: YamlPathConfig) -> Self {
        PathConfig {
            only: value
                .only
                .map(|v| v.into_iter().map(|p| p.into()).collect()),
            ignore: value.ignore.into_iter().map(|p| p.into()).collect(),
        }
    }
}

impl From<PathConfig> for YamlPathConfig {
    fn from(value: PathConfig) -> Self {
        YamlPathConfig {
            only: value
                .only
                .map(|v| v.into_iter().map(|p| p.into()).collect()),
            ignore: value.ignore.into_iter().map(|p| p.into()).collect(),
        }
    }
}

impl From<YamlRulesetList> for IndexMap<String, RulesetConfig> {
    fn from(value: YamlRulesetList) -> Self {
        value
            .0
            .into_iter()
            .map(|elem| (elem.name, elem.cfg.into()))
            .collect()
    }
}

impl From<IndexMap<String, RulesetConfig>> for YamlRulesetList {
    fn from(value: IndexMap<String, RulesetConfig>) -> Self {
        YamlRulesetList(
            value
                .into_iter()
                .map(|(name, cfg)| NamedRulesetConfig {
                    name,
                    cfg: cfg.into(),
                })
                .collect(),
        )
    }
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
            category: value.category.map(|v| v.category),
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
            category: value.category.map(|category| YamlRuleCategory { category }),
        }
    }
}

impl From<YamlBySubtree<AnyAsString>> for BySubtree<String> {
    fn from(value: YamlBySubtree<AnyAsString>) -> Self {
        value
            .0
            .into_iter()
            .map(|(k, v)| (SplitPath::from_string(k.as_str()), v.to_string()))
            .collect()
    }
}

impl From<BySubtree<String>> for YamlBySubtree<AnyAsString> {
    fn from(value: BySubtree<String>) -> Self {
        YamlBySubtree(
            value
                .iter()
                .map(|(k, v)| (k.to_string(), AnyAsString::Str(v.clone())))
                .collect(),
        )
    }
}

impl Default for AnyAsString {
    fn default() -> Self {
        AnyAsString::Str("".to_string())
    }
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
        ConfigFile, PathConfig, PathPattern, RuleConfig, RulesetConfig,
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
            let result = crate::config_file::parse_config_file(&cfg);
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
            let result = crate::config_file::parse_config_file(&cfg);
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

        let res = crate::config_file::parse_config_file(data);
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

        let res = crate::config_file::parse_config_file(data);
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

        let res = crate::config_file::parse_config_file(data);
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

        let res = crate::config_file::parse_config_file(data);
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

        let res = crate::config_file::parse_config_file(data);
        assert!(res.is_err());
        let data = r#"
rulesets:
  go-best-practices:
  go-security:
  go-best-practices:
    "#;

        let res = crate::config_file::parse_config_file(data);
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

        let res = crate::config_file::parse_config_file(data);
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

        let res = crate::config_file::parse_config_file(data);
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

        let res = crate::config_file::parse_config_file(data);
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

        let res = crate::config_file::parse_config_file(data);
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
                                        BySubtree::from([("", "100".to_string())]),
                                    ),
                                    (
                                        "arg2".to_string(),
                                        BySubtree::from([
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
                                        BySubtree::from([("", "300".to_string())]),
                                    ),
                                    (
                                        "arg4".to_string(),
                                        BySubtree::from([("cuatro", "400".to_string())]),
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
        let res = crate::config_file::parse_config_file(data);
        assert_eq!(expected, res.unwrap());
    }

    // Argument values
    #[test]
    fn test_parse_severities() {
        let data = r#"
rulesets:
  - python-security:
    rules:
      no-eval:
        severity: WARNING
      yes-eval:
        severity: NOTICE
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
                                arguments: IndexMap::new(),
                                severity: Some(RuleSeverity::Warning),
                                category: None,
                            },
                        ),
                        (
                            "yes-eval".to_string(),
                            RuleConfig {
                                paths: PathConfig::default(),
                                arguments: IndexMap::new(),
                                severity: Some(RuleSeverity::Notice),
                                category: None,
                            },
                        ),
                    ]),
                },
            )]),
            ..ConfigFile::default()
        };
        let res = crate::config_file::parse_config_file(data);
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

        let res = crate::config_file::parse_config_file(data);
        assert_eq!(expected, res.unwrap());
    }

    // No ruleset available in the data means that we have no configuration file
    // whatsoever and we should return Err
    #[test]
    fn test_parse_no_rulesets() {
        let data = r#"
    "#;
        let res = crate::config_file::parse_config_file(data);
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
            BySubtree::from([("", "3".to_string())]),
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
            BySubtree::from([("", "3".to_string()), ("my-path/to-file", "4".to_string())]),
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

    #[test]
    fn test_serialize_severities() {
        let mut rulesets = IndexMap::new();

        let mut rules: IndexMap<String, RuleConfig> = IndexMap::new();

        rules.insert(
            "rule-number-1".into(),
            RuleConfig {
                severity: Some(RuleSeverity::Warning),
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
      severity: WARNING
"
        .trim();

        assert_eq!(serialized, expected);
    }
}
