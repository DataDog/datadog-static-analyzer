use std::collections::HashMap;
use std::fmt;

use serde;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Debug, Serialize, Default, Clone)]
pub struct PathConfig {
    pub only: Option<Vec<String>>,
    pub ignore: Option<Vec<String>>,
}

#[derive(Deserialize, Debug, Serialize)]
pub struct RulesetConfig {
    #[serde(flatten)]
    pub paths: PathConfig,
    pub rules: Option<HashMap<String, PathConfig>>,
}

// the configuration file from the repository
#[derive(Deserialize, Debug, Serialize)]
pub struct ConfigFile {
    pub rulesets: HashMap<String, RulesetConfig>,
    #[serde(flatten)]
    pub paths: PathConfig,
    #[serde(rename(serialize = "ignore-gitignore", deserialize = "ignore-gitignore"))]
    pub ignore_gitignore: Option<bool>,
    #[serde(rename(serialize = "max-file-size-kb", deserialize = "max-file-size-kb"))]
    pub max_file_size_kb: Option<u64>,
}

impl fmt::Display for ConfigFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
