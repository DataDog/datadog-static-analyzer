// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026 Datadog, Inc.

use crate::model::rule::{RuleCategory, RuleSeverity};
use common::model::diff_aware::DiffAware;
use globset::{GlobBuilder, GlobMatcher};
use indexmap::IndexMap;
use sequence_trie::SequenceTrie;
use std::borrow::Borrow;
use std::fmt;
use std::fmt::{Debug, Formatter};
use std::path::{Path, PathBuf};

// A pattern for an 'only' or 'ignore' field. The 'glob' field contains a precompiled glob pattern,
// while the 'prefix' field contains a path prefix.
#[derive(Default, Clone)]
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

#[derive(Debug, Clone)]
pub enum ConfigMethod {
    File,
    RemoteConfiguration,
    RemoteConfigurationWithFile,
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
                .case_insensitive(true)
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

impl Debug for PathPattern {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let glob_str = if self.glob.is_some() {
            "Some(<opaque>)"
        } else {
            "None"
        };
        f.debug_struct("PathPattern")
            .field("prefix", &self.prefix)
            .field("glob", &glob_str)
            .finish()
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

// YAML-serializable schema version.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum YamlSchemaVersion {
    V1,
    V2,
    /// Input that isn't recognized as a supported schema version.
    Invalid(String),
}

const V1: &str = "v1";
const V2: &str = "v2";

impl serde::Serialize for YamlSchemaVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            YamlSchemaVersion::V1 => serializer.serialize_str(V1),
            YamlSchemaVersion::V2 => serializer.serialize_str(V2),
            YamlSchemaVersion::Invalid(s) => serializer.serialize_str(s),
        }
    }
}

impl<'de> serde::Deserialize<'de> for YamlSchemaVersion {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let mut s = String::deserialize(d)?;
        Ok(match s.as_str() {
            V1 => YamlSchemaVersion::V1,
            V2 => YamlSchemaVersion::V2,
            _ => {
                s.truncate(8);
                YamlSchemaVersion::Invalid(s)
            }
        })
    }
}

impl fmt::Display for YamlSchemaVersion {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let val = match self {
            YamlSchemaVersion::V1 => V1,
            YamlSchemaVersion::V2 => V2,
            YamlSchemaVersion::Invalid(text) => text.as_str(),
        };
        write!(f, "{val}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yaml_schema_version_deserialize() {
        let version = serde_yaml::from_str::<YamlSchemaVersion>("v1").unwrap();
        assert_eq!(version, YamlSchemaVersion::V1);
        let version = serde_yaml::from_str::<YamlSchemaVersion>("v2").unwrap();
        assert_eq!(version, YamlSchemaVersion::V2);
        let version = serde_yaml::from_str::<YamlSchemaVersion>("v9").unwrap();
        assert_eq!(version, YamlSchemaVersion::Invalid("v9".to_string()));
        let version = serde_yaml::from_str::<YamlSchemaVersion>("truncation test").unwrap();
        assert_eq!(version, YamlSchemaVersion::Invalid("truncati".to_string()));
    }
}
