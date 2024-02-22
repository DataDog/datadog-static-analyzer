use crate::model::config_file::{RuleConfig, RulesetConfig};
use serde::de::{Error, MapAccess, SeqAccess, Visitor};
use serde::Deserializer;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;

/// Special deserializer for a `RulesetConfig` map.
///
/// For backwards compatibility, we want to support lists of strings and maps from name to ruleset
/// config.
/// Lists of strings produce maps of empty `RulesetConfig`s.
/// Duplicate rulesets are rejected.
pub fn deserialize_rulesetconfigs<'de, D>(
    deserializer: D,
) -> Result<HashMap<String, RulesetConfig>, D::Error>
where
    D: Deserializer<'de>,
{
    struct RulesetConfigsVisitor {}
    impl<'de> Visitor<'de> for RulesetConfigsVisitor {
        type Value = HashMap<String, RulesetConfig>;

        fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
            formatter.write_str("a list of strings or map from string to ruleset configuration")
        }

        /// Deserializes a list of strings.
        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut out = HashMap::new();
            while let Some(name) = seq.next_element::<String>()? {
                if out.insert(name.clone(), RulesetConfig::default()).is_some() {
                    return Err(Error::custom(format!("duplicate ruleset: {}", name)));
                }
            }
            Ok(out)
        }

        /// Deserializes a map of string to `RulesetConfig`.
        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            let mut out = HashMap::new();
            while let Some((k, v)) = map.next_entry::<String, RulesetConfig>()? {
                if out.insert(k.clone(), v).is_some() {
                    return Err(Error::custom(format!("found duplicate ruleset: {}", k)));
                }
            }
            Ok(out)
        }
    }
    deserializer.deserialize_any(RulesetConfigsVisitor {})
}

/// Deserializer for a `RuleConfig` map which rejects duplicate rules.
pub fn deserialize_ruleconfigs<'de, D>(
    deserializer: D,
) -> Result<HashMap<String, RuleConfig>, D::Error>
where
    D: Deserializer<'de>,
{
    struct RuleConfigVisitor {}
    impl<'de> Visitor<'de> for RuleConfigVisitor {
        type Value = HashMap<String, RuleConfig>;

        fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
            formatter.write_str("an optional map from string to rule configuration")
        }

        /// Deserializes a map of string to `RuleConfig`.
        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            let mut out = HashMap::new();
            while let Some((k, v)) = map.next_entry::<String, RuleConfig>()? {
                if out.insert(k.clone(), v).is_some() {
                    return Err(Error::custom(format!("found duplicate rule: {}", k)));
                }
            }
            Ok(out)
        }
    }
    deserializer.deserialize_any(RuleConfigVisitor {})
}
