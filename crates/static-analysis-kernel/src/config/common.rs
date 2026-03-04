// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026 Datadog, Inc.

use crate::config::{file_legacy, file_v1};
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
    Legacy,
    /// A major and minor version. For example "v1.4" would be represented as `MajorMinor((1, 4))`
    MajorMinor((u8, u8)),
    /// Input that isn't recognized as a supported schema version.
    Invalid(String),
}

const LEGACY: &str = "v1";
const PREFIX: &str = "v";

/// Parses a string starting with "v" into a major and minor version.
fn parse_version(s: &str) -> Result<(u8, u8), &'static str> {
    let rest = s.strip_prefix(PREFIX).ok_or(r#"missing "v" prefix"#)?;

    let (left, right) = rest.split_once(".").ok_or(r#"missing "." separator"#)?;

    let major = left.parse::<u8>().map_err(|_| "invalid major version")?;
    let minor = right.parse::<u8>().map_err(|_| "invalid minor version")?;
    Ok((major, minor))
}

impl serde::Serialize for YamlSchemaVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            YamlSchemaVersion::Legacy => serializer.serialize_str(LEGACY),
            YamlSchemaVersion::MajorMinor((major, minor)) => {
                serializer.serialize_str(&format!("{PREFIX}{major}.{minor}"))
            }
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
        if s == LEGACY {
            return Ok(YamlSchemaVersion::Legacy);
        }

        Ok(match parse_version(&s) {
            Ok((major, minor)) => YamlSchemaVersion::MajorMinor((major, minor)),
            Err(_) => {
                s.truncate(8);
                YamlSchemaVersion::Invalid(s)
            }
        })
    }
}

impl fmt::Display for YamlSchemaVersion {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            YamlSchemaVersion::Legacy => write!(f, "{LEGACY}"),
            YamlSchemaVersion::MajorMinor((major, minor)) => write!(f, "{PREFIX}{major}.{minor}"),
            YamlSchemaVersion::Invalid(text) => write!(f, "{text}"),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("unsupported schema `{0}`")]
    UnsupportedSchema(String),
    #[error(transparent)]
    Parse(#[from] serde_yaml::Error),
}

/// A type intended to carry a "ConfigFile" as well as the schema version it was constructed
/// from. (This info is preserved for backwards compatibility so that legacy schemas can be output
/// by the datadog-static-analyzer-server.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum WithVersion<L, CS> {
    Legacy(L),
    CodeSecurity(CS),
}

/// Parses a YAML configuration for any schema.
pub fn parse_any_schema_yaml(
    config_contents: &str,
) -> Result<WithVersion<file_legacy::YamlConfigFile, file_v1::YamlConfigFile>, ConfigError> {
    #[derive(Debug, serde::Deserialize)]
    #[serde(rename_all = "kebab-case")]
    struct Version {
        schema_version: Option<YamlSchemaVersion>,
    }
    let v: Version = serde_yaml::from_str(config_contents).map_err(ConfigError::Parse)?;
    let schema_version = v.schema_version.unwrap_or(YamlSchemaVersion::Legacy);

    match schema_version {
        YamlSchemaVersion::Legacy => file_legacy::parse_yaml(config_contents)
            .map(WithVersion::Legacy)
            .map_err(ConfigError::Parse),
        YamlSchemaVersion::MajorMinor((1, _)) => {
            file_v1::parse_yaml(config_contents)
                .map(WithVersion::CodeSecurity)
                .map_err(|err| match err {
                    file_v1::ParseError::Parse(inner) => ConfigError::Parse(inner),
                    // This is in a branch where major == 1, so this is impossible.
                    file_v1::ParseError::WrongSchema(_) => unreachable!(),
                })
        }
        YamlSchemaVersion::MajorMinor((major, _)) => {
            Err(ConfigError::UnsupportedSchema(format!("v{major}.x")))
        }
        YamlSchemaVersion::Invalid(content) => Err(ConfigError::UnsupportedSchema(content)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yaml_schema_version_deserialize() {
        let version = serde_yaml::from_str::<YamlSchemaVersion>("v1").unwrap();
        assert_eq!(version, YamlSchemaVersion::Legacy);
        let version = serde_yaml::from_str::<YamlSchemaVersion>("v1.0").unwrap();
        assert_eq!(version, YamlSchemaVersion::MajorMinor((1, 0)));
        let version = serde_yaml::from_str::<YamlSchemaVersion>("v3.2").unwrap();
        assert_eq!(version, YamlSchemaVersion::MajorMinor((3, 2)));
        let version = serde_yaml::from_str::<YamlSchemaVersion>("v9").unwrap();
        assert_eq!(version, YamlSchemaVersion::Invalid("v9".to_string()));
        let version = serde_yaml::from_str::<YamlSchemaVersion>("truncation test").unwrap();
        assert_eq!(version, YamlSchemaVersion::Invalid("truncati".to_string()));
    }

    #[test]
    fn parse_any_legacy_v1_0() {
        // language=yaml
        let legacy = "\
schema-version: v1
rulesets:
  - java-security
";
        // language=yaml
        let schemaless = "\
rulesets:
  - java-security
";
        // language=yaml
        let v1_0 = "\
schema-version: v1.0
sast:
  use-default-rulesets: false
  use-rulesets:
    - java-security
";
        for (config_contents, expected_variant) in
            [(legacy, "v1"), (schemaless, "v1"), (v1_0, "v1.0")]
        {
            let parsed = parse_any_schema_yaml(config_contents).unwrap();
            match expected_variant {
                "v1" => assert!(matches!(parsed, WithVersion::Legacy(_))),
                "v1.0" => assert!(matches!(parsed, WithVersion::CodeSecurity(_))),
                // (If this triggers, you need to add a match arm from a &str to the new version, e.g "v1.1" to WithVersion::V1_1)
                _ => panic!("broken test setup: unknown schema `{expected_variant}`"),
            }
        }
    }

    #[test]
    fn config_errors() {
        // language=yaml
        let unknown_schema = "\
schema-version: v9
";
        assert!(matches!(
            parse_any_schema_yaml(unknown_schema), Err(ConfigError::UnsupportedSchema(v)) if v == "v9"));

        let invalid_yaml = "some \\ invalid: - '' syntax";
        let invalid_syntax_before_schema = format!(
            "\
{invalid_yaml}
schema-version: v1.0
"
        );

        let invalid_syntax_after_schema = format!(
            "\
schema-version: v1.0
{invalid_yaml}
"
        );
        for config_contents in [invalid_syntax_before_schema, invalid_syntax_after_schema] {
            assert!(matches!(
                parse_any_schema_yaml(&config_contents),
                Err(ConfigError::Parse(_))
            ));
        }
    }
}
