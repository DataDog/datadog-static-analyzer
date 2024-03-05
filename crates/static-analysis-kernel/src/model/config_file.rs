use serde;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

use crate::config_file::{deserialize_ruleconfigs, deserialize_rulesetconfigs};

// Lists of directories and glob patterns to include/exclude from the analysis.
#[derive(Deserialize, Serialize, Debug, PartialEq, Default, Clone)]
pub struct PathConfig {
    // Analyze only these directories and patterns.
    pub only: Option<Vec<String>>,
    // Do not analyze any of these directories and patterns.
    #[serde(default)]
    pub ignore: Vec<String>,
}

// Configuration for a single rule.
#[derive(Deserialize, Serialize, Debug, PartialEq, Default)]
pub struct RuleConfig {
    // Paths to include/exclude for this rule.
    #[serde(flatten)]
    pub paths: PathConfig,
}

// Configuration for a ruleset.
#[derive(Deserialize, Serialize, Debug, PartialEq, Default)]
pub struct RulesetConfig {
    // Paths to include/exclude for all rules in this ruleset.
    #[serde(flatten)]
    pub paths: PathConfig,
    // Rule-specific configurations.
    #[serde(default, deserialize_with = "deserialize_ruleconfigs")]
    pub rules: HashMap<String, RuleConfig>,
}

// The parsed configuration file without any legacy fields.
#[derive(Deserialize, Serialize, Debug, PartialEq, Default)]
#[serde(from = "RawConfigFile")]
pub struct ConfigFile {
    // Configurations for the rulesets.
    pub rulesets: HashMap<String, RulesetConfig>,
    // Paths to include/exclude from analysis.
    #[serde(flatten)]
    pub paths: PathConfig,
    // Ignore all the paths in the .gitignore file.
    #[serde(rename = "ignore-gitignore")]
    pub ignore_gitignore: Option<bool>,
    // Analyze only files up to this size.
    #[serde(rename = "max-file-size-kb")]
    pub max_file_size_kb: Option<u64>,
}

// The raw configuration file format with legacy fields and other quirks.
#[derive(Deserialize)]
struct RawConfigFile {
    // Configurations for the rulesets.
    #[serde(deserialize_with = "deserialize_rulesetconfigs")]
    rulesets: HashMap<String, RulesetConfig>,
    // Paths to include/exclude from analysis.
    #[serde(flatten)]
    paths: PathConfig,
    // For backwards compatibility. Its content will be added to paths.ignore.
    #[serde(rename = "ignore-paths")]
    ignore_paths: Option<Vec<String>>,
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
            rulesets: value.rulesets,
            paths: {
                let mut paths = value.paths;
                if let Some(ignore) = value.ignore_paths {
                    paths.ignore.extend(ignore);
                }
                paths
            },
            ignore_gitignore: value.ignore_gitignore,
            max_file_size_kb: value.max_file_size_kb,
        }
    }
}

impl fmt::Display for ConfigFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
