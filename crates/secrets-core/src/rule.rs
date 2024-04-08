// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::common::ByteSpan;
use crate::location::{PointLocator, PointSpan};
use crate::matcher::PatternId;
use crate::validator::ValidatorId;
use crate::Checker;
use std::collections::HashMap;
use std::fmt::{Debug, Display, Formatter};
use std::string::FromUtf8Error;
use std::sync::Arc;

/// A unique id that identifies a [`Rule`].
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
#[repr(transparent)]
pub struct RuleId(pub Arc<str>);

impl<T: AsRef<str>> From<T> for RuleId {
    fn from(value: T) -> Self {
        Self(Arc::from(value.as_ref()))
    }
}

impl RuleId {
    /// Returns the rule id as a string slice.
    pub fn as_str(&self) -> &str {
        self.0.as_ref()
    }
}

impl Display for RuleId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

pub struct Rule {
    id: RuleId,
    pattern_id: PatternId,
    validator_id: ValidatorId,
    pre_condition: Vec<Box<dyn Checker>>,
    match_checks: Vec<Box<dyn Checker>>,
}

impl Rule {
    pub fn new(
        id: RuleId,
        pattern_id: PatternId,
        validator_id: ValidatorId,
        pre_condition: Vec<Box<dyn Checker>>,
        match_checks: Vec<Box<dyn Checker>>,
    ) -> Self {
        Self {
            id,
            pattern_id,
            validator_id,
            pre_condition,
            match_checks,
        }
    }

    pub fn id(&self) -> &RuleId {
        &self.id
    }

    pub fn pattern_id(&self) -> PatternId {
        self.pattern_id
    }

    pub fn validator_id(&self) -> &ValidatorId {
        &self.validator_id
    }

    pub fn pre_condition(&self) -> &[Box<dyn Checker>] {
        self.pre_condition.as_slice()
    }

    pub fn match_checks(&self) -> &[Box<dyn Checker>] {
        self.match_checks.as_slice()
    }
}

/// A string that detected by a rule's [`Matcher`](crate::Matcher) that has passed the rule's [`Checker`](crate::Checker).
#[derive(Debug, Clone)]
pub struct RuleMatch {
    /// The id of the [`Rule`] that triggered this match.
    pub rule_id: RuleId,
    /// The top-level match
    pub matched: LocatedString,
    /// The captures of this match that will be sent to a validator.
    pub captures: HashMap<String, LocatedString>,
}

/// A `String` that has been located within its parent, providing metadata about the string's:
/// * [`ByteSpan`]
/// * [`PointSpan`]
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct LocatedString {
    pub inner: String,
    pub byte_span: ByteSpan,
    pub point_span: PointSpan,
}

impl LocatedString {
    pub fn as_str(&self) -> &str {
        self.inner.as_str()
    }

    /// Creates a [`LocatedString`], given a `PointLocator`.
    ///
    /// # Panics
    /// Panics if the `ByteSpan` would be out of bounds.
    pub fn from_locator(
        locator: &PointLocator,
        byte_span: ByteSpan,
    ) -> Result<LocatedString, FromUtf8Error> {
        let point_span = locator.get_point_span(byte_span);
        let inner = String::from_utf8(locator.data()[byte_span.as_range()].to_vec())?;
        Ok(LocatedString {
            inner,
            byte_span,
            point_span,
        })
    }
}

impl AsRef<str> for LocatedString {
    fn as_ref(&self) -> &str {
        self.inner.as_ref()
    }
}
