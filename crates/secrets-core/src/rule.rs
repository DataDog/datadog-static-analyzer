// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::common::ByteSpan;
use crate::location::PointSpan;
use crate::matcher::{MatcherId, PatternId};
use crate::validator::ValidatorId;
use std::fmt::{Debug, Display, Formatter};
use std::rc::Rc;
use std::sync::Arc;

/// A boolean logic expression supporting AND, OR, and NOT
#[derive(Debug, Clone)]
pub enum Predicate {
    /// A boolean expression detailing whether the input data is considered a match.
    Match {
        input: VariableKind,
        matcher_id: MatcherId,
        pattern_id: PatternId,
    },
    // TODO: these will eventually be implemented.
    And(Box<Predicate>, Box<Predicate>),
    Or(Box<Predicate>, Box<Predicate>),
    Not(Box<Predicate>),
}

impl Predicate {}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum VariableKind {
    /// A global variable that is contextual to the data. For example, if this is a file, this could
    /// be the file path, or the file contents.
    Global { variable: String, member: String },
    /// A reference to the name of a capture from a [`PatternMatch`].
    Capture { member: String },
}

impl VariableKind {
    /// Creates a [`VariableKind::Global`]
    pub fn global(variable: impl Into<String>, member: impl Into<String>) -> VariableKind {
        VariableKind::Global {
            variable: variable.into(),
            member: member.into(),
        }
    }

    /// Creats a [`VariableKind::Capture`]
    pub fn capture(member: impl Into<String>) -> VariableKind {
        VariableKind::Capture {
            member: member.into(),
        }
    }
}

impl Display for VariableKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            VariableKind::Global { variable, member } => {
                write!(f, "{}.{}", variable, member)
            }
            VariableKind::Capture { member } => {
                write!(f, "CAPTURES.{}", member)
            }
        }
    }
}

/// A unique id that identifies a pattern associated with a [`Rule`].
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
#[repr(transparent)]
pub struct RuleId(pub Arc<str>);

impl RuleId {
    /// Returns a shared reference to the underlying `str`.
    #[inline]
    pub fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

impl<T: AsRef<str>> From<T> for RuleId {
    fn from(value: T) -> Self {
        Self(Arc::from(value.as_ref()))
    }
}

// TODO: no pub
pub struct Rule {
    pub id: RuleId,
    pub match_logic: Vec<Rc<Predicate>>,
    pub validators: Vec<ValidatorId>,
}

impl Rule {
    pub fn new(
        id: RuleId,
        logic: impl Into<Vec<Predicate>>,
        validators: impl Into<Vec<ValidatorId>>,
    ) -> Self {
        let logic = logic.into().into_iter().map(Rc::new).collect::<Vec<_>>();
        Self {
            id,
            match_logic: logic,
            validators: validators.into(),
        }
    }
    pub fn match_logic(&self) -> &[Rc<Predicate>] {
        &self.match_logic
    }
}

/// An owned variant of a [`PatternMatch`].
///
/// A more semantic difference, though, is that a [`RuleMatch`] represents a match that
/// may have passed through multiple filters, whereas a [`PatternMatch`] only represents
/// the results of a single filter.
#[derive(Debug, Clone)]
pub struct RuleMatch {
    /// The id of the [`Rule`] that triggered this match.
    rule_id: RuleId,
    /// The captures of this match that will be sent to a validator.
    captures: LocatedCaptures,
}

impl RuleMatch {
    /// Returns the id of the [`Rule`] that generated this `PatternMatch`.
    pub fn rule_id(&self) -> &RuleId {
        &self.rule_id
    }

    /// Returns a reference to this match's captures.
    pub fn captures(&self) -> &LocatedCaptures {
        &self.captures
    }
}

/// An owned version of [`crate::capture::Captures`] that is additionally augmented with
/// the surrounding context of the capture.
#[derive(Debug, Clone)]
pub struct LocatedCaptures {
    surrounding_lines: LocatedString,
    name_slots: Option<Arc<Vec<Option<String>>>>,
    capture_slots: CaptureSlots,
}

impl LocatedCaptures {
    /// Returns the lines surrounding the entire capture.
    pub fn surrounding_lines(&self) -> &LocatedString {
        &self.surrounding_lines
    }

    /// Returns the capture with the given name.
    pub fn name(&self, name: impl AsRef<str>) -> Option<&LocatedString> {
        // Iterate `name_slots` from 1..n, searching for a name match.
        let name_slots = self.name_slots.as_ref()?;
        let slot_index = name_slots.as_ref().iter().skip(1).position(|slot| {
            slot.as_ref()
                .is_some_and(|capture_name| name.as_ref() == capture_name.as_str())
        })? + 1;

        self.get(slot_index)
    }

    /// Returns the capture with the given index.
    pub fn get(&self, index: usize) -> Option<&LocatedString> {
        self.capture_slots.0.get(index).and_then(|ls| ls.as_ref())
    }

    /// Returns a [`Capture`] representing the entire match.
    pub fn entire(&self) -> &LocatedString {
        self.capture_slots
            .0
            .first()
            .expect("capture slots should always have at least one member")
            .as_ref()
            .expect("the first capture should always be present")
    }

    pub fn captures_len(&self) -> usize {
        self.capture_slots.0.len()
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
#[repr(transparent)]
pub struct CaptureSlots(Vec<Option<LocatedString>>);

/// A `String` that has been located within its parent. Provides metadata about:
/// * [`ByteSpan`]
/// * [`PointSpan`]
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct LocatedString {
    inner: String,
    byte_span: ByteSpan,
    point_span: PointSpan,
}

impl LocatedString {
    pub fn as_str(&self) -> &str {
        self.inner.as_str()
    }
}

impl AsRef<str> for LocatedString {
    fn as_ref(&self) -> &str {
        self.inner.as_ref()
    }
}
