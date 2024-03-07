// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::capture::{Capture, Captures};
use crate::matcher::hyperscan::Hyperscan;
use std::cmp::Ordering;

pub mod hyperscan;

// NOTE: [`Matcher`] is conceptually a trait, however, given how small the current list of implemented
// matchers is, it's much less complicated to represent [`Matcher`] as an enum and use static dispatch.
//
// This means that we also "duplicate" logic with the enum [`MatcherKind`] (i.e. it's an exact replication of
// the `Matcher` enum itself). While this may seem repetitive and strange, it allows all of our
// call-sites to match off the [`Matcher::kind`] function, making a future refactor to a trait more straightforward.

#[derive(Debug, Clone)]
pub enum Matcher {
    Hyperscan(Hyperscan),
}

// NOTE: See top-level comment for why this mirrors [`Matcher`]
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum MatcherKind {
    Hyperscan,
}

impl Matcher {
    /// A human-friendly string id identifying the Matcher.
    pub fn id(&self) -> MatcherId {
        match self {
            Matcher::Hyperscan(hs) => hs.id(),
        }
    }

    /// The kind of Matcher.
    pub fn kind(&self) -> MatcherKind {
        match self {
            Matcher::Hyperscan(hs) => hs.kind(),
        }
    }

    pub fn scan_data<'a, 'b>(
        &'a mut self,
        data: &'b [u8],
    ) -> Result<impl IntoIterator<Item = PatternMatch<'b>> + 'a, MatcherError>
    where
        'b: 'a,
    {
        match self {
            Matcher::Hyperscan(ref mut hs) => hs.scan_data(data),
        }
    }
}

/// A unique id that identifies a [`Matcher`].
#[derive(Debug, Copy, Clone, Default, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct MatcherId(pub u32);

impl From<usize> for MatcherId {
    fn from(value: usize) -> Self {
        Self(value as u32)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum MatcherError {
    #[error("matcher couldn't complete scan")]
    Scan {
        matcher_id: &'static str,
        err: Box<dyn std::error::Error>,
    },
}

/// A unique id that identifies a pattern associated with a [`Matcher`].
#[derive(Debug, Copy, Clone, Default, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct PatternId(pub u32, MatcherId);

impl PatternId {
    pub fn new(pattern_id: usize, matcher_id: MatcherId) -> Self {
        Self(pattern_id as u32, matcher_id)
    }

    pub fn matcher_id(&self) -> MatcherId {
        self.1
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PatternMatch<'b> {
    /// The internal id of the pattern that generated this `PatternMatch`.
    pattern_id: PatternId,
    /// The original data that was scanned, which spans [0..n]
    full_data: &'b [u8],
    /// The captures of this match.
    captures: Captures<'b>,
}

impl PartialOrd for PatternMatch<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        let self_bs = self.entire().byte_span();
        let other_bs = other.entire().byte_span();
        Some(
            self_bs
                .start_index
                .cmp(&other_bs.start_index)
                .then(self_bs.end_index.cmp(&other_bs.end_index)),
        )
    }
}

impl<'b> PatternMatch<'b> {
    /// Returns the id of the pattern that generated this match.
    pub fn pattern_id(&self) -> PatternId {
        self.pattern_id
    }

    /// Returns the entire data that was the source of this `PatternMatch`.
    pub fn full_data(&self) -> &'b [u8] {
        self.full_data
    }

    /// Returns a reference to this PatternMatch's captures.
    pub fn captures(&self) -> &Captures<'b> {
        &self.captures
    }

    /// Returns a [`Capture`] representing the entire match.
    pub fn entire(&self) -> Capture<'b> {
        self.captures.entire()
    }
}
