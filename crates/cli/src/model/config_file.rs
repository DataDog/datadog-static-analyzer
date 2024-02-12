use std::fmt;

use serde;
use serde::{Deserialize, Serialize};

// the configuration file from the repository
#[derive(Deserialize, Debug, Serialize, PartialEq)]
pub struct ConfigFile {
    pub rulesets: Vec<String>,
    #[serde(rename(serialize = "ignore-paths", deserialize = "ignore-paths"))]
    pub ignore_paths: Option<Vec<String>>,
    #[serde(rename(serialize = "ignore-gitignore", deserialize = "ignore-gitignore"))]
    pub ignore_gitignore: Option<bool>,
    #[serde(rename(serialize = "max-file-size-kb", deserialize = "max-file-size-kb"))]
    pub max_file_size_kb: Option<u64>,
}

impl fmt::Display for ConfigFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let rules_string = self.rulesets.join(",");
        let ignore_path_string = match &self.ignore_paths {
            Some(i) => i.join(","),
            None => "".to_string(),
        };
        write!(
            f,
            "rulesets: {}, ignore paths: {}, ignore .gitignore: {}",
            rules_string,
            ignore_path_string,
            self.ignore_gitignore
                .map(|v| v.to_string())
                .unwrap_or("undefined".to_string())
        )
    }
}
