use anyhow::{anyhow, Context, Result};
use std::fs::File;
use std::io::Read;
use std::path::Path;

use crate::constants;
use crate::model;

fn parse_config_file(config_contents: &str) -> Result<model::config_file::ConfigFile> {
    Ok(serde_yaml::from_str(config_contents)?)
}

// We first try to read static-analysis.datadog.yml
// If it fails, we try to read static-analysis.datadog.yaml
// If the file does not exist, we return a Ok(None).
// If there is an error reading the file, we return a failure
pub fn read_config_file(path: &str) -> Result<Option<model::config_file::ConfigFile>> {
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

    // test when we have only rulesets. We should then have the ignore-paths set to None
    #[test]
    fn parse_config_file_with_rulesets_only() {
        let data = r#"
rulesets:
  - python-security
    "#;
        let res = parse_config_file(data);
        assert!(res.is_ok());
        assert!(res.unwrap().ignore_paths.is_none());
    }

    // test with everything: rulesets and ignore-paths
    #[test]
    fn parse_config_file_with_rulesets_and_ignore_paths() {
        let data = r#"
rulesets:
  - python-security
ignore-paths:
  - "**/test/**"
  - path1
    "#;
        let res = parse_config_file(data);
        assert!(res.is_ok());
        assert!(res.as_ref().unwrap().ignore_paths.is_some());
        let ignore_paths = &res.unwrap().ignore_paths.unwrap();
        assert_eq!(2, ignore_paths.len());
        assert_eq!("**/test/**", ignore_paths.get(0).unwrap().as_str());
        assert_eq!("path1", ignore_paths.get(1).unwrap().as_str());
    }

    // No ruleset available in the data means that we have no configuration file
    // whatsoever and we should return None
    #[test]
    fn parse_config_file_no_rulesets() {
        let data = r#"
    "#;
        let res = parse_config_file(data);
        assert!(res.is_err());
    }
}
