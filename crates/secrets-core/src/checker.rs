// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

pub mod boolean_logic;
pub use boolean_logic::BooleanLogic;
mod regex;
pub use regex::Regex;

use crate::matcher::PatternMatch;

/// A Checker provides a single predicate function that parses an input byte slice and returns
/// either `true` or `false` to indicate whether it passes the check or not.
///
/// In practice, this is used in two places:
/// * As part of a [`Rule`](crate::Rule), it controls whether data matched by a [`Matcher`](crate::Matcher)
/// will be promoted to a [`Candidate`](crate::validator::Candidate) and sent to a [`Validator`](crate::Validator).
/// * As part of a [`Validator`](crate::Validator), it pattern matches a validation result and maps it to a
/// [`SecretCategory`](crate::validator::SecretCategory).
pub trait Checker: Send + Sync {
    /// Given a byte slice, returns whether the check passes (`true`) or fails (`false`).
    fn check(&self, input: &[u8]) -> bool;
}

/// A PatternChecker provides a single predicate function that parses a [`PatternMatch`] and returns
/// either `true` or `false` to indicate whether it passes the check or not.
pub trait PatternChecker: Send + Sync {
    /// Given a `PatternMatch`, returns whether the check passes (`true`) or fails (`false`).
    fn check(&self, input: &PatternMatch) -> bool;
}
