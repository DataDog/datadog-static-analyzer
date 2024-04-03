// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::common::ByteSpan;
use crate::location::{PointLocator, PointSpan};
use crate::matcher::PatternId;
use crate::validator::ValidatorId;
use std::collections::HashMap;
use std::fmt::Debug;
use std::string::FromUtf8Error;
use std::sync::Arc;

/// A boolean logic expression supporting AND, OR, and NOT
#[derive(Debug, Clone)]
pub enum Expression {
    /// A predicate stating that a pattern with the given `PatternId` must match the source.
    IsMatch {
        source: MatchSource,
        pattern_id: PatternId,
    },
    /// Logical `AND`
    And(Arc<Expression>, Arc<Expression>),
    /// Logical `OR`
    Or(Arc<Expression>, Arc<Expression>),
    /// Logical `NOT`
    Not(Arc<Expression>),
}

/// A data source to search when evaluating a [`Rule`]'s matchers.
#[derive(Debug, Clone)]
pub enum MatchSource {
    Capture(String),
    Prior,
}

/// A unique id that identifies a [`Rule`].
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
#[repr(transparent)]
pub struct RuleId(pub Arc<str>);

impl From<&str> for RuleId {
    fn from(value: &str) -> Self {
        Self(Arc::from(value))
    }
}

impl From<String> for RuleId {
    fn from(value: String) -> Self {
        Self(Arc::from(value.as_str()))
    }
}

impl AsRef<str> for RuleId {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

#[derive(Debug, Clone)]
pub struct Rule {
    id: RuleId,
    conditions: Vec<Arc<RuleCondition>>,
    match_stages: Vec<Arc<Expression>>,
    validator_id: ValidatorId,
}

impl Rule {
    pub fn new(
        id: RuleId,
        conditions: impl Into<Vec<RuleCondition>>,
        match_stages: impl Into<Vec<Expression>>,
        validator_id: ValidatorId,
    ) -> Self {
        let match_stages = match_stages.into().into_iter().map(Arc::new).collect();
        let conditions = conditions.into().into_iter().map(Arc::new).collect();
        Self {
            id,
            conditions,
            match_stages,
            validator_id,
        }
    }

    pub fn id(&self) -> &RuleId {
        &self.id
    }

    pub fn match_stages(&self) -> &[Arc<Expression>] {
        &self.match_stages
    }

    pub fn validator_id(&self) -> &ValidatorId {
        &self.validator_id
    }
}

/// A predicate that must hold true for a rule to be considered "active" and able to generate a [`RuleMatch`].
#[derive(Debug)]
pub enum RuleCondition {
    FilePath(GlobAssertion<String>),
}

/// A Unix-style glob with either a positive or negative assertion:
/// * `MustMatch`: A pattern must match the provided glob
/// * `MustNotMatch`: A pattern must not match the provided glob
#[derive(Debug, Clone)]
pub enum GlobAssertion<T> {
    MustMatch(T),
    MustNotMatch(T),
}

/// A string that has passed all of a rule's matcher stages.
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
