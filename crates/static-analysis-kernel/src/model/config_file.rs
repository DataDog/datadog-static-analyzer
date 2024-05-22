use globset::{GlobBuilder, GlobMatcher};
use indexmap::IndexMap;
use sequence_trie::SequenceTrie;
use std::borrow::Borrow;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::path::{Path, PathBuf};

use crate::model::rule::{RuleCategory, RuleSeverity};

// A pattern for an 'only' or 'ignore' field. The 'glob' field contains a precompiled glob pattern,
// while the 'prefix' field contains a path prefix.
#[derive(Debug, Default, Clone)]
pub struct PathPattern {
    pub glob: Option<GlobMatcher>,
    pub prefix: PathBuf,
}

// Lists of directories and glob patterns to include/exclude from the analysis.
#[derive(Debug, PartialEq, Default, Clone)]
pub struct PathConfig {
    // Analyze only these directories and patterns.
    pub only: Option<Vec<PathPattern>>,
    // Do not analyze any of these directories and patterns.
    pub ignore: Vec<PathPattern>,
}

// A structure that stores values that depend on the position in the repository tree.
#[derive(Debug, PartialEq, Default, Clone)]
pub struct BySubtree<T>(SequenceTrie<String, T>);

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

// The key for operations on BySubtree.
pub struct SplitPath(Vec<String>);

impl SplitPath {
    pub fn from_string(path: &str) -> Self {
        SplitPath(
            path.split('/')
                .filter(|c| !c.is_empty())
                .map(&str::to_string)
                .collect(),
        )
    }
}

impl Display for SplitPath {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(self.0.join("/").as_str())
    }
}

impl<T> BySubtree<T> {
    pub fn new() -> Self {
        BySubtree(SequenceTrie::new())
    }
    pub fn get_ancestor(&self, path: &SplitPath) -> Option<&T> {
        self.0.get_ancestor(path.0.iter())
    }
    pub fn get_mut(&mut self, path: &SplitPath) -> Option<&mut T> {
        self.0.get_mut(path.0.iter())
    }
    pub fn insert(&mut self, path: &SplitPath, value: T) -> Option<T> {
        self.0.insert(path.0.iter(), value)
    }
    pub fn prefix_iter<'s, 'k>(&'s self, path: &'k SplitPath) -> BySubtreePrefixIter<'s, 'k, T> {
        BySubtreePrefixIter(self.0.prefix_iter(path.0.iter()))
    }
    pub fn iter(&self) -> BySubtreeIter<T> {
        self.into_iter()
    }
}

impl<V, const N: usize> From<[(String, V); N]> for BySubtree<V> {
    fn from(value: [(String, V); N]) -> Self {
        BySubtree::from_iter(value)
    }
}

impl<V> FromIterator<(String, V)> for BySubtree<V> {
    fn from_iter<T: IntoIterator<Item = (String, V)>>(iter: T) -> Self {
        let mut out = BySubtree::new();
        for (k, v) in iter {
            out.insert(&SplitPath::from_string(k.as_str()), v);
        }
        out
    }
}

impl<'a, T> IntoIterator for &'a BySubtree<T> {
    type Item = (SplitPath, &'a T);
    type IntoIter = BySubtreeIter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        BySubtreeIter(self.0.iter())
    }
}

pub struct BySubtreeIter<'a, T>(sequence_trie::Iter<'a, String, T>);

impl<'a, T> Iterator for BySubtreeIter<'a, T> {
    type Item = (SplitPath, &'a T);

    fn next(&mut self) -> Option<Self::Item> {
        self.0
            .next()
            .map(|(k, v)| (SplitPath(k.into_iter().cloned().collect()), v))
    }
}

pub struct BySubtreePrefixIter<'s, 'k, T>(
    sequence_trie::PrefixIter<'s, 'k, String, T, String, std::slice::Iter<'k, String>>,
);

impl<'s, 'k, T> Iterator for BySubtreePrefixIter<'s, 'k, T> {
    type Item = &'s T;

    fn next(&mut self) -> Option<Self::Item> {
        for item in self.0.by_ref() {
            if let Some(value) = item.value() {
                return Some(value);
            }
        }
        None
    }
}
