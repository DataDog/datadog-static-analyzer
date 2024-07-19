use crate::model::rule::{RuleCategory, RuleSeverity};
use common::model::diff_aware::DiffAware;
use globset::{GlobBuilder, GlobMatcher};
use indexmap::IndexMap;
use sequence_trie::SequenceTrie;
use std::borrow::Borrow;
use std::fmt;
use std::path::{Path, PathBuf};

// A pattern for an 'only' or 'ignore' field. The 'glob' field contains a precompiled glob pattern,
// while the 'prefix' field contains a path prefix.
#[derive(Debug, Default, Clone)]
pub struct PathPattern {
    pub glob: Option<GlobMatcher>,
    pub prefix: PathBuf,
}

impl DiffAware for PathPattern {
    fn generate_diff_aware_digest(&self) -> String {
        let glob = self
            .glob
            .as_ref()
            .map(|v| v.glob().to_string())
            .unwrap_or("".to_string());
        let prefix = self
            .prefix
            .to_str()
            .map(|v| v.to_string())
            .unwrap_or("".to_string());

        format!("{}:{}", glob, prefix)
    }
}

// Lists of directories and glob patterns to include/exclude from the analysis.
#[derive(Debug, PartialEq, Default, Clone)]
pub struct PathConfig {
    // Analyze only these directories and patterns.
    pub only: Option<Vec<PathPattern>>,
    // Do not analyze any of these directories and patterns.
    pub ignore: Vec<PathPattern>,
}

impl DiffAware for PathConfig {
    fn generate_diff_aware_digest(&self) -> String {
        let only = self
            .only
            .as_ref()
            .map(|v| {
                v.iter()
                    .map(|w| w.generate_diff_aware_digest())
                    .collect::<Vec<String>>()
                    .join(",")
            })
            .unwrap_or("".to_string());

        let ignore = self
            .ignore
            .iter()
            .map(|v| v.generate_diff_aware_digest())
            .collect::<Vec<String>>()
            .join(",");

        format!("{}:{}", only, ignore)
    }
}

// A type that stores values that depend on the position in the repository tree.
pub type BySubtree<T> = SequenceTrie<PathComponent, T>;

// Configuration for a single rule.
#[derive(Debug, PartialEq, Default, Clone)]
pub struct RuleConfig {
    // Paths to include/exclude for this rule.
    pub paths: PathConfig,
    // Arguments to pass to this rule.
    pub arguments: IndexMap<String, BySubtree<String>>,
    // Override this rule's severity.
    pub severity: Option<BySubtree<RuleSeverity>>,
    // Override this rule's category.
    pub category: Option<RuleCategory>,
}

// Configuration for a ruleset.
#[derive(Debug, PartialEq, Default, Clone)]
pub struct RulesetConfig {
    // Paths to include/exclude for all rules in this ruleset.
    pub paths: PathConfig,
    // Rule-specific configurations.
    pub rules: IndexMap<String, RuleConfig>,
}

// The parsed configuration file without any legacy fields.
#[derive(Debug, PartialEq, Default, Clone)]
pub struct ConfigFile {
    // Configurations for the rulesets.
    pub rulesets: IndexMap<String, RulesetConfig>,
    // Paths to include/exclude from analysis.
    pub paths: PathConfig,
    // Ignore all the paths in the .gitignore file.
    pub ignore_gitignore: Option<bool>,
    // Analyze only files up to this size.
    pub max_file_size_kb: Option<u64>,
    // Do not analyze generated files.
    pub ignore_generated_files: Option<bool>,
}

impl fmt::Display for ConfigFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl PathPattern {
    pub fn matches(&self, path: &str) -> bool {
        self.glob
            .as_ref()
            .map(|g| g.is_match(path))
            .unwrap_or(false)
            || Path::new(path).starts_with(&self.prefix)
    }
}

impl From<String> for PathPattern {
    fn from(value: String) -> Self {
        PathPattern {
            glob: GlobBuilder::new(&value)
                .literal_separator(true)
                .empty_alternates(true)
                .backslash_escape(true)
                .build()
                .map(|g| g.compile_matcher())
                .ok(),
            prefix: PathBuf::from(value),
        }
    }
}

impl Borrow<str> for PathPattern {
    fn borrow(&self) -> &str {
        self.prefix.to_str().unwrap_or("")
    }
}

impl From<PathPattern> for String {
    fn from(value: PathPattern) -> Self {
        value.prefix.display().to_string()
    }
}

impl PartialEq for PathPattern {
    fn eq(&self, other: &Self) -> bool {
        self.prefix.eq(&other.prefix)
    }
}

impl PathConfig {
    pub fn allows_file(&self, file_name: &str) -> bool {
        !self.ignore.iter().any(|pattern| pattern.matches(file_name))
            && match &self.only {
                None => true,
                Some(only) => only.iter().any(|pattern| pattern.matches(file_name)),
            }
    }
}

// An opaque path component.
#[derive(Debug, PartialEq, Eq, Hash, Default, Clone)]
pub struct PathComponent(String);

impl DiffAware for PathComponent {
    fn generate_diff_aware_digest(&self) -> String {
        self.0.clone()
    }
}

// The key for operations on BySubtree.
pub type SplitPath = Vec<PathComponent>;

// Generates a SplitPath from a path string, separated by '/'.
pub fn split_path<S>(path: S) -> SplitPath
where
    S: Borrow<str>,
{
    path.borrow()
        .split('/')
        .filter(|c| !c.is_empty())
        .map(|s| PathComponent(s.to_string()))
        .collect()
}

// Generates a path string from a SplitPath.
pub fn join_path(path: &SplitPath) -> String {
    path.iter()
        .map(|c| c.0.clone())
        .collect::<Vec<_>>()
        .join("/")
}

// Generates a BySubtree from an iterable of tuples of path string and value.
pub fn values_by_subtree<T, S, I>(src: I) -> BySubtree<T>
where
    S: Borrow<str>,
    I: IntoIterator<Item = (S, T)>,
{
    let mut out = BySubtree::new();
    for (k, v) in src {
        out.insert(&split_path(k), v);
    }
    out
}
