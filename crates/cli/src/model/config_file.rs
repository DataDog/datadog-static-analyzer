use std::collections::HashMap;
use std::fmt;

use crate::model::serialization::{deserialize_ruleconfigs, deserialize_rulesetconfigs};

use serde;
use serde::{Deserialize, Serialize};

// Lists of directories and glob patterns to include/exclude from the analysis.
#[derive(Deserialize, Serialize, Debug, PartialEq, Default)]
pub struct PathConfig {
    // Analyze only these directories and patterns.
    pub only: Option<Vec<String>>,
    // Do not analyze any of these directories and patterns.
    pub ignore: Option<Vec<String>>,
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
    pub rules: Option<HashMap<String, RuleConfig>>,
}

// the configuration file from the repository
#[derive(Deserialize, Serialize, Debug, PartialEq, Default)]
pub struct ConfigFile {
    // Configurations for the rulesets.
    #[serde(deserialize_with = "deserialize_rulesetconfigs")]
    pub rulesets: HashMap<String, RulesetConfig>,
    // Paths to include/exclude from analysis.
    #[serde(flatten)]
    pub paths: PathConfig,
    // For backwards compatibility. Its content will be added to paths.ignore.
    #[serde(rename(serialize = "ignore-paths", deserialize = "ignore-paths"))]
    pub ignore_paths: Option<Vec<String>>,
    // Ignore all the paths in the .gitignore file.
    #[serde(rename(serialize = "ignore-gitignore", deserialize = "ignore-gitignore"))]
    pub ignore_gitignore: Option<bool>,
    // Analyze only files up to this size.
    #[serde(rename(serialize = "max-file-size-kb", deserialize = "max-file-size-kb"))]
    pub max_file_size_kb: Option<u64>,
}

impl fmt::Display for ConfigFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
