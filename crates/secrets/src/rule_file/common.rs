// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use std::fmt::{Display, Formatter};

/// Adds a [`serde::Deserialize`] implementation for an enum of the following signature:
///
/// ```text
/// pub enum ExampleEnum<'de, T, U, /* .. */>
/// where
///     T: serde::Deserialize<'de>,
///     U: serde::Deserialize<'de>,
///     // ...
/// {
///     Golf(T),
///     Hotel(U),
///     // ...
/// }
/// ```
/// Usage:
/// ```text
/// deserialize_enum_exactly_one_of!(
///     ExampleEnum,
///     "example",
///     // The caller must manually implement the mapping of Rust enum variant names to their plain-text
///     // representation. This is conceptually equivalent to using `#[serde(rename = "...")]`
///     {
///         "golf_alias" => ExampleEnum::Golf,
///         "hotel" => ExampleEnum::Hotel,
///     }
/// );
/// ```
/// This implementation deserializes a map-like object into an `ExampleEnum`, but first validates
/// to ensure that the map-like object has only one key-value pair, that the key equals the literal
/// specified in the macro, and the value is a valid deserialization of the Rust value.
/// For example, given
/// ```yaml
/// parent:
///   example:
///     golf_alias: [1, 2, 3]  // Let's say it's ExampleEnum::Golf(Vec<usize>)
/// ```
/// will deserialize to `ExampleEnum::Golf(_)`
///
/// and
/// ```yaml
/// parent:
///   example:
///     hotel:        // Let's say it's ExampleEnum::Hotel(InnerStruct { nested: usize, field: usize })
///       nested: 1
///       field: 2
/// ```
/// will deserialize to `ExampleEnum::Hotel(_)`
///
/// However,
/// ```yaml
/// parent:
///   example:
///     golf_alias: [1, 2, 3]
///     hotel: { 'nested': 1, 'field': 2 }
/// ```
/// will throw a deserialization/validation error because only one matching key must exist.
macro_rules! deserialize_enum_exactly_one_of {
    (
        $enum_ident:ident,
        $unit:literal,
        {$($key:literal => $variant:path),* $(,)?}
    ) => {
        impl<'de> serde::Deserialize<'de> for $enum_ident {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct MapVisitor;

                impl<'de> serde::de::Visitor<'de> for MapVisitor {
                    type Value = $enum_ident;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                        write!(formatter, "a supported `{}`", $unit)
                    }

                    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
                    where
                        A: serde::de::MapAccess<'de>,
                    {
                        let first_key = map
                            .next_key::<&str>()?
                            .ok_or(serde::de::Error::custom(format!("expected a single `{}`", $unit)))?;

                        let raw: $enum_ident = match first_key {
                            $($key => Ok($variant(map.next_value()?)),)*
                            other => Err(serde::de::Error::custom(format!("unknown {} `{other}`", $unit))),
                        }?;

                        if let Some(key) = map.next_key::<&str>()? {
                            return Err(serde::de::Error::custom(format!(
                                "invalid use of {} `{key}`: expecting a single {} and already found `{first_key}`",
                                $unit, $unit
                            )));
                        }
                        Ok(raw)
                    }
                }

                deserializer.deserialize_map(MapVisitor)
            }
        }
    };
}
pub(crate) use deserialize_enum_exactly_one_of;

/// Provides the default derive implementations for a struct representing a JSON object in a rule file.
///
/// ```text
/// #[derive(Debug, Clone, serde::Deserialize)]
/// #[serde(deny_unknown_fields, rename_all = "kebab-case")]
/// struct Example(usize);
/// ```
macro_rules! raw_struct {
    ($raw_struct:item) => {
        #[derive(Debug, Clone, serde::Deserialize)]
        #[serde(deny_unknown_fields, rename_all = "kebab-case")]
        $raw_struct
    };

    ($($raw_struct:item)+) => {
        $(raw_struct!($raw_struct);)+
    };
}
pub(crate) use raw_struct;

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(untagged, rename_all = "kebab-case")]
pub enum StringsOrInts {
    Strings(Vec<String>),
    Integers(Vec<isize>),
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(untagged, rename_all = "kebab-case")]
pub enum StringOrInt {
    String(String),
    Integer(isize),
}

impl Display for StringOrInt {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            StringOrInt::String(str) => write!(f, "{}", str),
            StringOrInt::Integer(int) => write!(f, "{}", int),
        }
    }
}

#[allow(dead_code)]
#[rustfmt::skip]
#[cfg(test)]
mod tests {
    #[derive(Debug)]
    enum Restricted {
        Echo(usize),
        Foxtrot(Vec<isize>),
        Golf(String),
    }
    deserialize_enum_exactly_one_of!(
        Restricted,
        "restricted",
        {
            "echo" => Restricted::Echo,
            "foxtrot" => Restricted::Foxtrot,
            "golf-alias" => Restricted::Golf,
        }
    );

    #[derive(Debug, serde::Deserialize)]
    struct RawFile {
        restricted: Restricted,
        other: String,
    }

    #[test]
    fn exactly_one_of_not_multi() {
        let contents = "
restricted:
  echo: 5
other: 'hello'
        ";
        assert!(serde_yaml::from_str::<RawFile>(contents).is_ok());
        let contents = "
restricted:
  foxtrot: [-1, 0, 1]
other: 'hello'
        ";
        assert!(serde_yaml::from_str::<RawFile>(contents).is_ok());
        let contents = "
restricted:
  echo: 5
  foxtrot: [-1, 0, 1]
other: 'hello'
        ";
        let result = serde_yaml::from_str::<RawFile>(contents);
        assert!(result.unwrap_err().to_string().contains("invalid use of restricted `foxtrot`"));
        let contents = "
restricted:
  foxtrot: [-1, 0, 1]
  echo: 5
other: 'hello'
        ";
        let result = serde_yaml::from_str::<RawFile>(contents);
        assert!(result.unwrap_err().to_string().contains("invalid use of restricted `echo`"));
    }

    #[test]
    fn exactly_one_of_not_zero() {
        let contents = "
restricted:
other: 'hello'
        ";
        let result = serde_yaml::from_str::<RawFile>(contents);
        assert!(result.unwrap_err().to_string().contains("expected a single `restricted`"));
    }

    #[test]
    fn exactly_one_of_alias() {
        let contents = "
restricted:
  golf-alias: 'hotel india'
other: 'hello'
        ";
        assert!(serde_yaml::from_str::<RawFile>(contents).is_ok(), "variant alias should work");
    }

    #[test]
    fn raw_struct_case() {
        raw_struct! {
            struct RawFile {
                some_field: usize,
            }
        }
        let contents = "
some-field: 123
        ";
        assert!(serde_yaml::from_str::<RawFile>(contents).is_ok(), "should be renamed with kebab-case");
    }

    #[test]
    fn raw_struct_reject_unexpected() {
        raw_struct! {
            struct RawFile {
                first: Vec<usize>,
                second: Vec<usize>,
            }
        }
        let contents = "
first: [1, 2, 3]
second: [4, 5, 6]
unexpected: [7, 8, 9]
        ";
        assert!(serde_yaml::from_str::<RawFile>(contents).is_err(), "should reject field `unexpected`");
    }
}
