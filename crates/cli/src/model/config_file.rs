use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;

use serde;
use serde::de::{Error, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

// Lists of directories and glob patterns to include/exclude from the analysis.
#[derive(Deserialize, Serialize, Debug, PartialEq, Default)]
pub struct PathConfig {
    // Analyze only these directories and patterns.
    pub only: Option<Vec<String>>,
    // Do not analyze any of these directories and patterns.
    pub ignore: Option<Vec<String>>,
}

// Configuration for a single rule.
#[derive(Deserialize, Serialize, Debug, PartialEq, Default)]
pub struct RuleConfig {
    // Paths to include/exclude for this rule.
    #[serde(flatten)]
    pub paths: PathConfig,
}

// Configuration for a ruleset.
#[derive(Deserialize, Serialize, Debug, PartialEq, Default)]
pub struct RulesetConfig {
    // Paths to include/exclude for all rules in this ruleset.
    #[serde(flatten)]
    pub paths: PathConfig,
    // Rule-specific configurations.
    pub rules: Option<HashMap<String, RuleConfig>>,
}

// Holder for ruleset configurations, to aid in (de)serialization.
#[derive(Serialize, Debug, PartialEq, Default)]
pub struct RulesetConfigs(pub HashMap<String, RulesetConfig>);

// the configuration file from the repository
#[derive(Deserialize, Serialize, Debug, PartialEq, Default)]
pub struct ConfigFile {
    // Configurations for the rulesets.
    pub rulesets: RulesetConfigs,
    // Paths to include/exclude from analysis.
    #[serde(flatten)]
    pub paths: PathConfig,
    // For backwards compatibility. Its content will be added to paths.ignore.
    #[serde(rename(serialize = "ignore-paths", deserialize = "ignore-paths"))]
    pub ignore_paths: Option<Vec<String>>,
    // Ignore all the paths in the .gitignore file.
    #[serde(rename(serialize = "ignore-gitignore", deserialize = "ignore-gitignore"))]
    pub ignore_gitignore: Option<bool>,
    // Analyze only files up to this size.
    #[serde(rename(serialize = "max-file-size-kb", deserialize = "max-file-size-kb"))]
    pub max_file_size_kb: Option<u64>,
}

impl fmt::Display for ConfigFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

// Used as an intermediate deserialization step when lists of maps are involved.
struct NamedRulesetConfig {
    pub name: String,
    pub cfg: RulesetConfig,
}

// Special deserializer for RulesetConfigs.
// For backwards compatibility, we want to support lists of strings and maps from name to ruleset
// config. Also, to be forgiving of mistakes, we want to support lists of maps (see
// NamedRulesetConfig's deserializer for more details).
impl<'de> Deserialize<'de> for RulesetConfigs {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct RulesetConfigsVisitor {}
        impl<'de> Visitor<'de> for RulesetConfigsVisitor {
            type Value = RulesetConfigs;

            fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                formatter.write_str(
                    "a list of strings, map of string to ruleset configuration, or list of maps",
                )
            }

            // Deserialize a list using the NamedRulesetConfig deserializer.
            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut out = RulesetConfigs(HashMap::new());
                while let Some(rc) = seq.next_element::<NamedRulesetConfig>()? {
                    out.0.insert(rc.name, rc.cfg);
                }
                Ok(out)
            }

            // Deserialize a map. The values are RulesetConfig.
            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut out = RulesetConfigs(HashMap::new());
                while let Some((k, v)) = map.next_entry::<String, RulesetConfig>()? {
                    out.0.insert(k, v);
                }
                Ok(out)
            }
        }
        deserializer.deserialize_any(RulesetConfigsVisitor {})
    }
}

// Deserializer for NamedRulesetConfig.
// This handles three cases:
// 1. A string is deserialized as a RulesetConfig without options.
// 2. A single-element map from a name to a RulesetConfig is converted to a NamedRulesetConfig.
// 3. A map with more than 1 element is deserialized elementwise and its content populated into
//    a NamedRulesetConfig.
// The last case sounds weird, but is intended to account for the case where the user forgets
// to indent the map.
// We go through all this trouble for backwards compatibility: previous versions of the static
// analyzer use a string list for the `rulesets` configuration field, but new versions want to
// be able to use a map. Therefore, we need to be able to deserialize both. And we know that
// users may make mistakes if they ever need to change from a string list to a map, so we try
// hard to accommodate them.
impl<'de> Deserialize<'de> for NamedRulesetConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct NamedRulesetConfigVisitor {}
        impl<'de> Visitor<'de> for NamedRulesetConfigVisitor {
            type Value = NamedRulesetConfig;

            fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                formatter.write_str(
                    "a string, ruleset configuration, or map from string to ruleset configuration",
                )
            }

            // String. Build a NamedRulesetConfig without options.
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                self.visit_string(v.to_string())
            }

            // String. Build a NamedRulesetConfig without options.
            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: Error,
            {
                Ok(NamedRulesetConfig {
                    name: v,
                    cfg: RulesetConfig::default(),
                })
            }

            // Map. See the description above.
            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut out = match map.next_entry::<String, RulesetConfig>()? {
                    None => {
                        return Err(Error::missing_field("name"));
                    }
                    Some((k, v)) => NamedRulesetConfig { name: k, cfg: v },
                };
                // If the user forgot to indent, we populate the object field by field.
                while let Some(x) = map.next_key::<String>()? {
                    match x.as_str() {
                        "only" => {
                            if out.cfg.paths.only.is_some() {
                                return Err(Error::duplicate_field("only"));
                            } else {
                                out.cfg.paths.only = Some(map.next_value()?);
                            }
                        }
                        "ignore" => {
                            if out.cfg.paths.ignore.is_some() {
                                return Err(Error::duplicate_field("ignore"));
                            } else {
                                out.cfg.paths.ignore = Some(map.next_value()?);
                            }
                        }
                        "rules" => {
                            if out.cfg.rules.is_some() {
                                return Err(Error::duplicate_field("rules"));
                            } else {
                                out.cfg.rules = Some(map.next_value()?);
                            }
                        }
                        "" => {
                            // Ignore empty keys
                        }
                        otherwise => {
                            return Err(Error::custom(format!("unknown field: {}", otherwise)));
                        }
                    }
                }
                Ok(out)
            }
        }
        deserializer.deserialize_any(NamedRulesetConfigVisitor {})
    }
}
