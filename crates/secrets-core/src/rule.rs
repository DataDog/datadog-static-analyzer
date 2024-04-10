// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::checker::PatternChecker;
use crate::common::ByteSpan;
use crate::location::{PointLocator, PointSpan};
use crate::matcher::{PatternId, PatternMatch};
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

/// A function that takes a [`PatternMatch`] and extracts a slice of bytes.
pub type DynPatternChecker = dyn Fn(&PatternMatch) -> bool + Send + Sync;

/// A [`PatternChecker`]
pub struct TargetedChecker(Box<DynPatternChecker>);

impl TargetedChecker {
    /// Creates a boxed and casted `PatternChecker` that operates on the bytes of the entire candidate.
    pub fn candidate<T: Checker + 'static>(checker: T) -> Box<dyn PatternChecker> {
        let checker: Box<dyn Checker> = Box::new(checker);
        let pm_checker = move |pm: &PatternMatch| -> bool {
            let data = pm.entire().as_bytes();
            checker.check(data)
        };
        Box::new(Self(Box::new(pm_checker)))
    }

    /// Creates a `TargetedChecker` that operates on a named capture.
    pub fn named_capture<T: Checker + 'static>(
        capture_name: impl Into<String>,
        checker: T,
    ) -> Box<dyn PatternChecker> {
        let checker: Box<dyn Checker> = Box::new(checker);
        let capture_name = capture_name.into();
        let pm_checker = move |pm: &PatternMatch| -> bool {
            let data = pm
                .captures()
                .name(&capture_name)
                .map(|capture| capture.as_bytes());
            data.map_or(false, |data| checker.check(data))
        };
        Box::new(Self(Box::new(pm_checker)))
    }
}

impl PatternChecker for TargetedChecker {
    fn check(&self, input: &PatternMatch) -> bool {
        self.0(input)
    }
}

pub struct Rule {
    id: RuleId,
    pattern_id: PatternId,
    validator_id: ValidatorId,
    pre_condition: Vec<Box<dyn PatternChecker>>,
    match_checks: Vec<Box<dyn PatternChecker>>,
}

impl Rule {
    pub fn new(
        id: RuleId,
        pattern_id: PatternId,
        validator_id: ValidatorId,
        pre_condition: Vec<Box<dyn PatternChecker>>,
        match_checks: Vec<Box<dyn PatternChecker>>,
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

    pub fn pre_condition(&self) -> &[Box<dyn PatternChecker>] {
        self.pre_condition.as_slice()
    }

    pub fn match_checks(&self) -> &[Box<dyn PatternChecker>] {
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

#[cfg(test)]
mod tests {
    use crate::checker::Regex;
    use crate::matcher::hyperscan::{Hyperscan, HyperscanBuilder};
    use crate::matcher::PatternMatch;
    use crate::rule::TargetedChecker;

    fn make_hyperscan() -> Hyperscan {
        let mut hsb = HyperscanBuilder::new(1.into());
        let _ = hsb.add_regex(r#"(?<cap_one>\d{3})---(?<cap_two>[a-z]{3})---(?<cap_three>\d{3})"#);
        hsb.try_compile().unwrap()
    }

    /// From a `Checker`, we can generate a `PatternChecker` that uses a [`PatternMatch`] candidate.
    #[test]
    fn pm_targeted_candidate() {
        let mut hs = make_hyperscan();
        let cursor = hs.scan_data("123---def---456".as_bytes()).unwrap();
        let pattern_match = &cursor.into_iter().collect::<Vec<_>>()[0];

        let regex = Regex::try_new(".{3}-+.{3}-+.{3}").unwrap();
        let pm_checker = TargetedChecker::candidate(regex);
        assert!(pm_checker.check(pattern_match));

        let regex = Regex::try_new("[a-z]{4}").unwrap();
        let pm_checker = TargetedChecker::candidate(regex);
        assert!(!pm_checker.check(pattern_match));
    }

    /// From a `Checker`, we can generate a `PatternChecker` that can target a named candidate.
    #[test]
    fn pm_targeted_named_capture() {
        let mut hs = make_hyperscan();
        let cursor = hs.scan_data("123---def---456".as_bytes()).unwrap();
        let pattern_match = &cursor.into_iter().collect::<Vec<_>>()[0];

        let regex = Regex::try_new(r#"\d+"#).unwrap();
        let pm_checker = TargetedChecker::named_capture("cap_one", regex);
        assert!(pm_checker.check(pattern_match));
        let regex = Regex::try_new(r#"\d+"#).unwrap();
        let pm_checker = TargetedChecker::named_capture("cap_two", regex);
        assert!(!pm_checker.check(pattern_match));
    }
}
