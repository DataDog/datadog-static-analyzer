use crate::model::config_file::{RuleConfig, RulesetConfig};
use serde;
use serde::de::{Error, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
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
            while let Some(nrc) = seq.next_element::<NamedRulesetConfig>()? {
                if out.insert(nrc.name.clone(), nrc.cfg).is_some() {
                    return Err(Error::custom(format!("duplicate ruleset: {}", nrc.name)));
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

/// Holder for ruleset configurations specified in lists.
struct NamedRulesetConfig {
    name: String,
    cfg: RulesetConfig,
}

/// Special deserializer for ruleset list items.
///
/// As we've changed the format, we are going to get a mixture of old format configurations,
/// new format configurations, and configurations that have been converted but have syntax errors.
///
/// To be friendly, we try extra hard to parse the configuration file the user intended, even in
/// the face of syntax errors:
///
/// This is the modern syntax:
/// ```yaml
/// rulesets:
///   ruleset1:
///   ruleset2:
///     ignore:
///       - "foo"
///   ruleset3:
/// ```
/// This is the old syntax:
/// ```yaml
/// rulesets:
///   - ruleset1
///   - ruleset2
///   - ruleset3
/// ```
/// This is an invalid syntax that we try to parse here:
/// ```yaml
/// rulesets:
///   - ruleset1
///   - ruleset2:
///       ignore:
///         - "foo"
///   - ruleset3:
///     ignore:
///       - "foo"
/// ```
/// (Note the indentation for the difference between the last two rulesets.)
impl<'de> Deserialize<'de> for NamedRulesetConfig {
    fn deserialize<D>(deserializer: D) -> Result<NamedRulesetConfig, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct NamedRulesetConfigVisitor {}
        impl<'de> Visitor<'de> for NamedRulesetConfigVisitor {
            type Value = NamedRulesetConfig;
            fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                formatter.write_str("a string or ruleset configuration")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                self.visit_string(v.to_string())
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: Error,
            {
                Ok(NamedRulesetConfig {
                    name: v,
                    cfg: RulesetConfig::default(),
                })
            }

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
                            if !out.cfg.paths.ignore.is_empty() {
                                return Err(Error::duplicate_field("ignore"));
                            } else {
                                out.cfg.paths.ignore = map.next_value()?;
                            }
                        }
                        "rules" => {
                            if !out.cfg.rules.is_empty() {
                                return Err(Error::duplicate_field("rules"));
                            } else {
                                out.cfg.rules = map.next_value()?;
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
