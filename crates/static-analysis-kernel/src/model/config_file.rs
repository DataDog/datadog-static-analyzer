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

#[derive(Debug, PartialEq, Clone)]
pub struct BySubtree<T>(SequenceTrie<String, T>);

// Configuration for a single rule.
#[derive(Debug, PartialEq, Default, Clone)]
pub struct RuleConfig {
    // Paths to include/exclude for this rule.
    pub paths: PathConfig,
    pub arguments: IndexMap<String, BySubtree<String>>,
    pub severity: Option<BySubtree<RuleSeverity>>,
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

// The parsed configuration file.
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
    // Ignore any generated files.
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

impl PathConfig {
    pub fn allows(&self, file_name: &str) -> bool {
        !self.ignore.iter().any(|pattern| pattern.matches(file_name))
            && match &self.only {
                None => true,
                Some(only) => only.iter().any(|pattern| pattern.matches(file_name)),
            }
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

impl From<PathPattern> for String {
    fn from(value: PathPattern) -> Self {
        value.prefix.to_str().unwrap_or("").to_string()
    }
}

impl Borrow<str> for PathPattern {
    fn borrow(&self) -> &str {
        self.prefix.to_str().unwrap_or("")
    }
}

impl PartialEq for PathPattern {
    fn eq(&self, other: &Self) -> bool {
        self.prefix.eq(&other.prefix)
    }
}

pub struct SplitPath(Vec<String>);

impl SplitPath {
    pub fn from_string(path: &str) -> Self {
        SplitPath(
            path.split('/')
                .filter(|p| !p.is_empty())
                .map(|p| p.to_string())
                .collect(),
        )
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Display for SplitPath {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            f.write_str("/")
        } else {
            f.write_str(&self.0.join("/"))
        }
    }
}

impl<V, const N: usize> From<[(&str, V); N]> for BySubtree<V> {
    fn from(arr: [(&str, V); N]) -> Self {
        Self::from_iter(arr.into_iter().map(|(k, v)| (SplitPath::from_string(k), v)))
    }
}

impl<V> FromIterator<(SplitPath, V)> for BySubtree<V> {
    fn from_iter<T: IntoIterator<Item = (SplitPath, V)>>(iter: T) -> Self {
        let mut out = BySubtree::new();
        for item in iter {
            out.insert(&item.0, item.1);
        }
        out
    }
}

impl<T> BySubtree<T> {
    pub fn new() -> Self {
        BySubtree(SequenceTrie::new())
    }
    pub fn from_value(value: T) -> Self {
        Self::from([("", value)])
    }
    pub fn insert(&mut self, path: &SplitPath, value: T) -> Option<T> {
        self.0.insert(path.0.iter(), value)
    }
    pub fn get(&self, path: &SplitPath) -> Option<&T> {
        self.0.get_ancestor(path.0.iter())
    }
    pub fn get_mut(&mut self, path: &SplitPath) -> Option<&mut T> {
        self.0.get_mut(path.0.iter())
    }
    pub fn iter(&self) -> SubtreeIter<T> {
        SubtreeIter(self.0.iter())
    }
    pub fn prefix_iter<'a, 'b>(&'a self, path: &'b SplitPath) -> SubtreePrefixIter<T>
    where
        'b: 'a,
    {
        SubtreePrefixIter(self.0.prefix_iter(path.0.iter()))
    }
}

pub struct SubtreeIter<'a, T>(sequence_trie::Iter<'a, String, T>);

impl<'a, T> Iterator for SubtreeIter<'a, T> {
    type Item = (SplitPath, &'a T);

    fn next(&mut self) -> Option<Self::Item> {
        self.0
            .next()
            .map(|(k, v)| (SplitPath(k.iter().map(|p| p.to_string()).collect()), v))
    }
}

pub struct SubtreePrefixIter<'a, 'b, T>(
    sequence_trie::PrefixIter<'a, 'b, String, T, String, std::slice::Iter<'b, String>>,
);

impl<'a, T> Iterator for SubtreePrefixIter<'a, '_, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<Self::Item> {
        for node in self.0.by_ref() {
            if let Some(value) = node.value() {
                return Some(value);
            }
        }
        None
    }
}

impl<T> Default for BySubtree<T> {
    fn default() -> Self {
        BySubtree::new()
    }
}
