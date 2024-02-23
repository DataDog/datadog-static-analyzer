use anyhow::{anyhow, Context, Result};
use std::fs::File;
use std::io::Read;
use std::path::Path;

use crate::constants;
use crate::model;

fn parse_config_file(config_contents: &str) -> Result<model::config_file::ConfigFileWithWarnings> {
    Ok(serde_yaml::from_str(config_contents)?)
}

// We first try to read static-analysis.datadog.yml
// If it fails, we try to read static-analysis.datadog.yaml
// If the file does not exist, we return a Ok(None).
// If there is an error reading the file, we return a failure
pub fn read_config_file(path: &str) -> Result<Option<model::config_file::ConfigFileWithWarnings>> {
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
        assert_eq!(expected, res.unwrap().config_file);
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
        assert_eq!(expected, res.unwrap().config_file);
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
        assert_eq!(expected, res.unwrap().config_file);
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
        assert_eq!(expected, res.unwrap().config_file);
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
        assert_eq!(expected, res.unwrap().config_file);
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
