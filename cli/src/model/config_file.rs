use std::fmt;

use serde;
use serde::{Deserialize, Serialize};

// the configuration file from the repository
#[derive(Deserialize, Debug, Serialize)]
pub struct ConfigFile {
    pub rulesets: Vec<String>,
    #[serde(rename(serialize = "ignore-paths", deserialize = "ignore-paths"))]
    pub ignore_paths: Option<Vec<String>>,
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
            "rulesets: {}, ignore paths: {}",
            rules_string, ignore_path_string
        )
    }
}
