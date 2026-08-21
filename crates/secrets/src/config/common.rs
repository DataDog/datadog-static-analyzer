// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026 Datadog, Inc.

use std::fmt;
use std::fmt::Formatter;

// YAML-serializable schema version.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum YamlSchemaVersion {
    /// A major and minor version. For example "v1.4" would be represented as `MajorMinor((1, 4))`
    MajorMinor((u8, u8)),
    /// Input that isn't recognized as a supported schema version.
    Invalid(String),
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yaml_schema_version_deserialize() {
        let version = serde_yaml::from_str::<YamlSchemaVersion>("v1").unwrap();
        assert_eq!(version, YamlSchemaVersion::Invalid("v1".to_string()));
        let version = serde_yaml::from_str::<YamlSchemaVersion>("v1.0").unwrap();
        assert_eq!(version, YamlSchemaVersion::MajorMinor((1, 0)));
        let version = serde_yaml::from_str::<YamlSchemaVersion>("v3.2").unwrap();
        assert_eq!(version, YamlSchemaVersion::MajorMinor((3, 2)));
        let version = serde_yaml::from_str::<YamlSchemaVersion>("v9").unwrap();
        assert_eq!(version, YamlSchemaVersion::Invalid("v9".to_string()));
        let version = serde_yaml::from_str::<YamlSchemaVersion>("truncation test").unwrap();
        assert_eq!(version, YamlSchemaVersion::Invalid("truncati".to_string()));
    }
}
