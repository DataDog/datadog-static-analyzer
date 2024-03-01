use std::collections::HashMap;

// Lists of directories and glob patterns to include/exclude from the analysis.
#[derive(Debug, PartialEq, Default, Clone)]
pub struct PathConfig {
    // Analyze only these directories and patterns.
    pub only: Option<Vec<String>>,
    // Do not analyze any of these directories and patterns.
    pub ignore: Vec<String>,
}

// Configuration for a single rule.
#[derive(Debug, PartialEq, Default)]
pub struct RuleConfig {
    // Paths to include/exclude for this rule.
    pub paths: PathConfig,
}

// Configuration for a ruleset.
#[derive(Debug, PartialEq, Default)]
pub struct RulesetConfig {
    // Paths to include/exclude for all rules in this ruleset.
    pub paths: PathConfig,
    // Rule-specific configurations.
    pub rules: HashMap<String, RuleConfig>,
}

// The static analyzer's configuration.
#[derive(Debug, PartialEq, Default)]
pub struct ConfigFile {
    // Configurations for the rulesets.
    pub rulesets: HashMap<String, RulesetConfig>,
    // Paths to include/exclude from analysis.
    pub paths: PathConfig,
    // Ignore all the paths in the .gitignore file.
    pub ignore_gitignore: Option<bool>,
    // Analyze only files up to this size.
    pub max_file_size_kb: Option<u64>,
}
