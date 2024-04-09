// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

pub mod boolean_logic;
pub use boolean_logic::BooleanLogic;
mod regex;
pub use regex::Regex;

use crate::capture::Captures;
use std::borrow::Cow;
use std::path::Path;

/// A Checker provides a single predicate function that parses an input byte slice and returns
/// either `true` or `false` to indicate whether it passes the check or not.
///
/// In practice, this is used in two places:
/// * As part of a [`Rule`](crate::Rule), it controls whether data matched by a [`Matcher`](crate::Matcher)
/// will be promoted to a [`Candidate`](crate::validator::Candidate) and sent to a [`Validator`](crate::Validator).
/// * As part of a [`Validator`](crate::Validator), it pattern matches a validation result and maps it to a
/// [`SecretCategory`](crate::validator::SecretCategory).
pub trait Checker: Send + Sync {
    /// Given a set of data, returns whether the check passes (`true`) or fails (`false`).
    fn check(&self, input: &CheckData) -> bool;
}

/// A struct containing the various data sources a [`Checker`] has access to.
#[derive(Debug, Clone, Default)]
pub struct CheckData<'d> {
    /// The entire byte slice of data
    full_data: Option<&'d [u8]>,
    /// The captures of the candidate found by a [`Matcher`].
    captures: Option<Cow<'d, Captures<'d>>>,
    /// A file path to associate with the data being scanned.
    file_path: Option<&'d Path>,
}

impl<'d> CheckData<'d> {
    pub fn new(
        full_data: Option<&'d [u8]>,
        captures: Option<Cow<'d, Captures<'d>>>,
        file_path: Option<&'d Path>,
    ) -> CheckData<'d> {
        Self {
            full_data,
            captures,
            file_path,
        }
    }

    /// Constructs a `CheckData` with the entire input as both the `candidate` and the `full_data`.
    ///
    /// # Example
    /// ```rust
    /// # use crate::secrets_core::checker::CheckData;
    /// let full_data = "hello world".as_bytes().to_vec();
    /// let check_data = CheckData::from_data(full_data.as_slice());
    ///
    /// let candidate = check_data.candidate().unwrap();
    /// assert_eq!(candidate, full_data.as_slice());
    /// ```
    pub fn from_data(full_data: &'d [u8]) -> CheckData<'d> {
        let captures = Captures::new_from_data(full_data);
        CheckData {
            full_data: Some(full_data),
            captures: Some(Cow::Owned(captures)),
            ..Default::default()
        }
    }

    /// Returns a file path associated with the data, if it exists.
    pub fn file_path(&self) -> Option<&'d Path> {
        self.file_path
    }

    /// Returns a byte slice of the full data, if it exists.
    pub fn full_data(&self) -> Option<&'d [u8]> {
        self.full_data
    }

    /// Returns a byte slice of the entire candidate, if it exists.
    pub fn candidate(&self) -> Option<&'d [u8]> {
        self.captures.as_ref().map(|captures| {
            match captures {
                Cow::Owned(captures) => captures,
                Cow::Borrowed(captures) => *captures,
            }
            .entire()
            .as_bytes()
        })
    }
}
