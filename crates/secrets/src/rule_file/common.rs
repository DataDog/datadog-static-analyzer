// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use std::fmt::{Debug, Display, Formatter};
use std::ops::Deref;

/// A transparent wrapper struct that instructs `serde_yaml` to deserialize the
/// inner as an externally tagged enum.
///
/// This is required because the behavior of `serde_yaml` when deserializing maps changed in version 0.9.0.
///
/// Pre-0.9.0, you could deserialize a YAML object into an externally-tagged enum, like so:
/// ```rust
/// #[derive(Debug, serde::Deserialize)]
/// #[serde(rename_all = "lowercase")]
/// enum Restricted {
///     Echo(usize),
///     Foxtrot(usize),
/// }
///
/// let yaml = r#"
/// restricted:
///  echo: 5
/// "#;
/// let des = serde_yaml::from_str::<Restricted>(yaml);
/// // Before v0.9.0, the following was true:
/// // assert!(matches!(des, Ok(Restricted::Echo(n)) if n == 5));
/// // Post 0.9.0, the following is true:
/// assert!(des.is_err_and(|err| err.to_string().contains("invalid type: map")));
/// ```
///
/// Now, in order to get this behavior, we have to deserialize with [`serde_yaml::with::singleton_map`]
/// to achieve the same effect.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(transparent)]
pub struct SingletonMap<T>(#[serde(with = "serde_yaml::with::singleton_map_recursive")] pub T)
where
    T: serde::de::DeserializeOwned + Clone + Debug;

impl<T> Deref for SingletonMap<T>
where
    T: serde::de::DeserializeOwned + Clone + Debug,
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> SingletonMap<T>
where
    T: serde::de::DeserializeOwned + Clone + Debug,
{
    /// Consumes the `SingletonMap`, returning the inner value
    pub fn into_inner(self) -> T {
        self.0
    }
}

/// Provides the default derive implementations for an item representing a JSON object in a rule file.
///
/// ```text
/// #[derive(Debug, Clone, serde::Deserialize)]
/// #[serde(deny_unknown_fields, rename_all = "kebab-case")]
/// struct Example(usize);
/// ```
macro_rules! raw_item {
    ($raw_struct:item) => {
        #[derive(Debug, Clone, serde::Deserialize)]
        #[serde(deny_unknown_fields, rename_all = "kebab-case")]
        $raw_struct
    };

    ($($raw_struct:item)+) => {
        $(raw_item!($raw_struct);)+
    };
}
pub(crate) use raw_item;

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

#[rustfmt::skip]
#[cfg(test)]
mod tests {
    #[allow(dead_code)]
    #[test]
    fn raw_struct_case() {
        raw_item! {
            struct RawFile {
                some_field: usize,
            }
        }
        let contents = "
some-field: 123
        ";
        assert!(serde_yaml::from_str::<RawFile>(contents).is_ok(), "should be renamed with kebab-case");
    }

    #[allow(dead_code)]
    #[test]
    fn raw_struct_reject_unexpected() {
        raw_item! {
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
