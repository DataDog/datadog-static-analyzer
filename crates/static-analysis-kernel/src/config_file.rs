use anyhow::Result;
use sequence_trie::SequenceTrie;
use serde::de::{Error, MapAccess, SeqAccess, Unexpected, Visitor};
use serde::{Deserialize, Deserializer};
use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;

use crate::model::config_file::{ArgumentValues, ConfigFile, RuleConfig, RulesetConfig};

pub fn parse_config_file(config_contents: &str) -> Result<ConfigFile> {
    Ok(serde_yaml::from_str(config_contents)?)
}

const SCHEMA_VERSION: &str = "v1";

pub fn deserialize_schema_version<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    struct SchemaVersionVisitor {}
    impl<'de> Visitor<'de> for SchemaVersionVisitor {
        type Value = String;

        fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
            formatter.write_fmt(format_args!("a \"{}\" string", SCHEMA_VERSION))
        }

        fn visit_str<E>(self, v: &str) -> std::result::Result<Self::Value, E>
        where
            E: Error,
        {
            if v != SCHEMA_VERSION {
                Err(Error::invalid_value(Unexpected::Str(v), &self))
            } else {
                Ok(v.to_string())
            }
        }
    }
    deserializer.deserialize_string(SchemaVersionVisitor {})
}

pub fn get_default_schema_version() -> String {
    SCHEMA_VERSION.to_string()
}

type Argument = (String, String);

type ArgumentsByPrefix = SequenceTrie<String, Vec<Argument>>;

#[derive(Clone)]
// Used to extract rule arguments in the analyzer.
pub struct ArgumentProvider {
    by_rule: HashMap<String, ArgumentsByPrefix>,
}

impl ArgumentProvider {
    pub fn new() -> ArgumentProvider {
        ArgumentProvider {
            by_rule: HashMap::new(),
        }
    }

    pub fn from(config: &ConfigFile) -> Self {
        let mut provider = ArgumentProvider::new();
        for (ruleset_name, ruleset_cfg) in &config.rulesets {
            for (rule_shortname, rule_cfg) in &ruleset_cfg.rules {
                for (arg_name, arg_values) in &rule_cfg.arguments {
                    let rule_name = format!("{}/{}", ruleset_name, rule_shortname);
                    for (prefix, value) in &arg_values.by_subtree {
                        provider.add_argument(&rule_name, prefix, arg_name, value);
                    }
                }
            }
        }
        provider
    }

    pub fn add_argument(&mut self, rule_name: &str, path: &str, argument: &str, value: &str) {
        let prefix: Vec<String> = path
            .split('/')
            .filter(|c| !c.is_empty())
            .map(|c| c.to_string())
            .collect();
        let trie = self.by_rule.entry(rule_name.to_string()).or_default();
        match trie.get_mut(prefix.iter()) {
            None => {
                trie.insert(
                    prefix.iter(),
                    vec![(argument.to_string(), value.to_string())],
                );
            }
            Some(v) => {
                v.push((argument.to_string(), value.to_string()));
            }
        };
    }

    /// Returns the arguments that apply to the given file and the given rule.
    pub fn get_arguments(&self, filename: &str, rulename: &str) -> HashMap<String, String> {
        let mut out = HashMap::new();
        if let Some(by_prefix) = self.by_rule.get(rulename) {
            for args in by_prefix
                .prefix_iter(filename.split('/').filter(|c| !c.is_empty()))
                .filter_map(|x| x.value())
            {
                // Longer prefixes appear last, so they'll override arguments from shorter prefixes.
                out.extend(args.clone());
            }
        }
        out
    }
}

impl Default for ArgumentProvider {
    fn default() -> Self {
        ArgumentProvider::new()
    }
}

/// Special deserializer for a `RulesetConfig` map.
///
/// For backwards compatibility, we want to support lists of strings and maps from name to ruleset
/// config.
/// Lists of strings produce maps of empty `RulesetConfig`s.
/// Duplicate rulesets are rejected.
pub fn deserialize_rulesetconfigs<'de, D>(
    deserializer: D,
) -> Result<HashMap<String, RulesetConfig>, D::Error>
where
    D: Deserializer<'de>,
{
    struct RulesetConfigsVisitor {}
    impl<'de> Visitor<'de> for RulesetConfigsVisitor {
        type Value = HashMap<String, RulesetConfig>;

        fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
            formatter.write_str("a list of ruleset configurations")
        }

        /// Deserializes a list of strings.
        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut out = HashMap::new();
            while let Some(nrc) = seq.next_element::<NamedRulesetConfig>()? {
                if out.insert(nrc.name.clone(), nrc.cfg).is_some() {
                    return Err(Error::custom(format!("duplicate ruleset: {}", nrc.name)));
                }
            }
            if out.is_empty() {
                return Err(Error::custom("no rulesets were specified"));
            }
            Ok(out)
        }
    }
    deserializer.deserialize_any(RulesetConfigsVisitor {})
}

/// Holder for ruleset configurations specified in lists.
struct NamedRulesetConfig {
    name: String,
    cfg: RulesetConfig,
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
    fn deserialize<D>(deserializer: D) -> Result<NamedRulesetConfig, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct NamedRulesetConfigVisitor {}
        impl<'de> Visitor<'de> for NamedRulesetConfigVisitor {
            type Value = NamedRulesetConfig;
            fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                formatter.write_str("a string or ruleset configuration")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                self.visit_string(v.to_string())
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: Error,
            {
                Ok(NamedRulesetConfig {
                    name: v,
                    cfg: RulesetConfig::default(),
                })
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut out = match map.next_entry::<String, ()>()? {
                    None => {
                        return Err(Error::missing_field("name"));
                    }
                    Some((k, _)) => NamedRulesetConfig {
                        name: k,
                        cfg: RulesetConfig::default(),
                    },
                };
                // Populate the object field by field.
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
                        _ => {
                            // Ignore empty and other fields
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
pub fn deserialize_ruleconfigs<'de, D>(
    deserializer: D,
) -> Result<HashMap<String, RuleConfig>, D::Error>
where
    D: Deserializer<'de>,
{
    struct RuleConfigVisitor {}
    impl<'de> Visitor<'de> for RuleConfigVisitor {
        type Value = HashMap<String, RuleConfig>;

        fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
            formatter.write_str("an optional map from string to rule configuration")
        }

        /// Deserializes a map of string to `RuleConfig`.
        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            let mut out = HashMap::new();
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

impl<'de> Deserialize<'de> for ArgumentValues {
    fn deserialize<D>(deserializer: D) -> Result<ArgumentValues, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ArgumentValuesVisitor {}
        impl<'de> Visitor<'de> for ArgumentValuesVisitor {
            type Value = ArgumentValues;

            fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                formatter.write_str("a string or map from subtree to string")
            }

            // Cast pretty much every primitive type to a string.
            fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
            where
                E: Error,
            {
                self.visit_string(v.to_string())
            }

            fn visit_u128<E>(self, v: u128) -> Result<Self::Value, E>
            where
                E: Error,
            {
                self.visit_string(v.to_string())
            }

            fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
            where
                E: Error,
            {
                self.visit_string(v.to_string())
            }

            fn visit_i128<E>(self, v: i128) -> Result<Self::Value, E>
            where
                E: Error,
            {
                self.visit_string(v.to_string())
            }

            fn visit_f64<E>(self, v: f64) -> Result<Self::Value, E>
            where
                E: Error,
            {
                self.visit_string(v.to_string())
            }

            fn visit_bool<E>(self, v: bool) -> Result<Self::Value, E>
            where
                E: Error,
            {
                self.visit_string(v.to_string())
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E>
            where
                E: Error,
            {
                self.visit_string("".to_string())
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                self.visit_string(v.to_string())
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: Error,
            {
                Ok(ArgumentValues {
                    by_subtree: HashMap::from([("".to_string(), v)]),
                })
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut by_subtree = HashMap::new();
                while let Some((key, value)) = map.next_entry::<String, String>()? {
                    let prefix = if key == "/" || key == "**" { "" } else { &key };
                    if by_subtree.insert(prefix.to_string(), value).is_some() {
                        return Err(Error::custom(format!("repeated key: {}", key)));
                    }
                }
                Ok(ArgumentValues { by_subtree })
            }
        }
        deserializer.deserialize_any(ArgumentValuesVisitor {})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::config_file::{
        ArgumentValues, ConfigFile, PathConfig, RuleConfig, RulesetConfig,
    };
    use std::collections::HashMap;
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
            rulesets: HashMap::from([
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
            rulesets: HashMap::from([(
                "python-security".to_string(),
                RulesetConfig {
                    paths: PathConfig::default(),
                    rules: HashMap::from([(
                        "no-eval".to_string(),
                        RuleConfig {
                            paths: PathConfig {
                                only: Some(vec!["py/**".to_string().into()]),
                                ignore: vec!["py/insecure/**".to_string().into()],
                            },
                            arguments: HashMap::new(),
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
            rulesets: HashMap::from([(
                "python-security".to_string(),
                RulesetConfig {
                    paths: PathConfig::default(),
                    rules: HashMap::from([
                        (
                            "no-eval".to_string(),
                            RuleConfig {
                                paths: PathConfig::default(),
                                arguments: HashMap::from([
                                    (
                                        "arg1".to_string(),
                                        ArgumentValues {
                                            by_subtree: HashMap::from([(
                                                "".to_string(),
                                                "100".to_string(),
                                            )]),
                                        },
                                    ),
                                    (
                                        "arg2".to_string(),
                                        ArgumentValues {
                                            by_subtree: HashMap::from([
                                                ("".to_string(), "200".to_string()),
                                                ("uno".to_string(), "201".to_string()),
                                                ("uno/dos".to_string(), "202".to_string()),
                                                ("tres".to_string(), "203".to_string()),
                                            ]),
                                        },
                                    ),
                                ]),
                            },
                        ),
                        (
                            "yes-eval".to_string(),
                            RuleConfig {
                                paths: PathConfig::default(),
                                arguments: HashMap::from([
                                    (
                                        "arg3".to_string(),
                                        ArgumentValues {
                                            by_subtree: HashMap::from([(
                                                "".to_string(),
                                                "300".to_string(),
                                            )]),
                                        },
                                    ),
                                    (
                                        "arg4".to_string(),
                                        ArgumentValues {
                                            by_subtree: HashMap::from([(
                                                "cuatro".to_string(),
                                                "400".to_string(),
                                            )]),
                                        },
                                    ),
                                ]),
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
            rulesets: HashMap::from([("python-security".to_string(), RulesetConfig::default())]),
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
    fn test_argument_provider_returns_arg_for_default_prefix() {
        let mut argument_provider = ArgumentProvider::new();
        argument_provider.add_argument("rule", "/", "arg", "value");

        let expected = HashMap::from([("arg".to_string(), "value".to_string())]);
        assert_eq!(argument_provider.get_arguments("a", "rule"), expected);
        assert_eq!(argument_provider.get_arguments("b/c", "rule"), expected);
    }

    #[test]
    fn test_argument_provider_returns_arg_for_path_prefix() {
        let mut argument_provider = ArgumentProvider::new();
        argument_provider.add_argument("rule", "a/b/c", "arg", "value");

        let expected = HashMap::from([("arg".to_string(), "value".to_string())]);
        assert!(argument_provider.get_arguments("a", "rule").is_empty());
        assert!(argument_provider.get_arguments("a/b", "rule").is_empty());
        assert_eq!(argument_provider.get_arguments("a/b/c", "rule"), expected);
        assert_eq!(argument_provider.get_arguments("a/b/c/d", "rule"), expected);
    }

    #[test]
    fn test_argument_provider_returns_arg_for_longest_path_prefix() {
        let mut argument_provider = ArgumentProvider::new();
        argument_provider.add_argument("rule", "a/b", "arg", "first");
        argument_provider.add_argument("rule", "a/b/c", "arg", "second");

        let expected_first = HashMap::from([("arg".to_string(), "first".to_string())]);
        let expected_second = HashMap::from([("arg".to_string(), "second".to_string())]);
        assert!(argument_provider.get_arguments("a", "rule").is_empty());
        assert_eq!(
            argument_provider.get_arguments("a/b", "rule"),
            expected_first
        );
        assert_eq!(
            argument_provider.get_arguments("a/b/c", "rule"),
            expected_second
        );
        assert_eq!(
            argument_provider.get_arguments("a/b/c/d", "rule"),
            expected_second
        );
    }

    #[test]
    fn test_argument_provider_returns_multiple_args_in_path() {
        let mut argument_provider = ArgumentProvider::new();
        argument_provider.add_argument("rule", "a", "arg1", "first_1");
        argument_provider.add_argument("rule", "a", "arg2", "first_2");
        argument_provider.add_argument("rule", "a/b", "arg3", "first_3");
        argument_provider.add_argument("rule", "a/b/c", "arg1", "second_1");

        assert_eq!(
            argument_provider.get_arguments("a", "rule"),
            HashMap::from([
                ("arg1".to_string(), "first_1".to_string()),
                ("arg2".to_string(), "first_2".to_string())
            ])
        );
        assert_eq!(
            argument_provider.get_arguments("a/b", "rule"),
            HashMap::from([
                ("arg1".to_string(), "first_1".to_string()),
                ("arg2".to_string(), "first_2".to_string()),
                ("arg3".to_string(), "first_3".to_string())
            ])
        );
        assert_eq!(
            argument_provider.get_arguments("a/b/c", "rule"),
            HashMap::from([
                ("arg1".to_string(), "second_1".to_string()),
                ("arg2".to_string(), "first_2".to_string()),
                ("arg3".to_string(), "first_3".to_string())
            ])
        );
    }

    #[test]
    fn test_argument_provider_is_independent_from_insertion_order() {
        let mut argument_provider = ArgumentProvider::new();
        argument_provider.add_argument("rule", "a/b/c", "arg1", "second_1");
        argument_provider.add_argument("rule", "a", "arg2", "first_2");
        argument_provider.add_argument("rule", "a/b", "arg3", "first_3");
        argument_provider.add_argument("rule", "a", "arg1", "first_1");

        assert_eq!(
            argument_provider.get_arguments("a", "rule"),
            HashMap::from([
                ("arg1".to_string(), "first_1".to_string()),
                ("arg2".to_string(), "first_2".to_string())
            ])
        );
        assert_eq!(
            argument_provider.get_arguments("a/b", "rule"),
            HashMap::from([
                ("arg1".to_string(), "first_1".to_string()),
                ("arg2".to_string(), "first_2".to_string()),
                ("arg3".to_string(), "first_3".to_string())
            ])
        );
        assert_eq!(
            argument_provider.get_arguments("a/b/c", "rule"),
            HashMap::from([
                ("arg1".to_string(), "second_1".to_string()),
                ("arg2".to_string(), "first_2".to_string()),
                ("arg3".to_string(), "first_3".to_string())
            ])
        );
    }
}
