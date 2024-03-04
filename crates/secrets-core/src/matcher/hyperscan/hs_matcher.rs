// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use std::iter::FusedIterator;
use vectorscan::scan::ScanStatus;

use crate::capture::Captures;
use crate::matcher::hyperscan::pattern_set::{NamedPattern, PatternSet};
use crate::matcher::hyperscan::scratch::Scratch;
use crate::matcher::hyperscan::transform::MatchIter;
use crate::matcher::{MatcherError, MatcherId, MatcherKind, PatternId, PatternMatch};
use std::ops::ControlFlow;
use std::slice::{Iter, IterMut};
use std::sync::Arc;
use vectorscan::database::BlockDatabase;
use vectorscan::HsMatch;

#[derive(Debug, Clone)]
pub struct Hyperscan {
    id: MatcherId,
    database: Arc<BlockDatabase>,
    patterns: Vec<NamedPattern>,
    hs_scratch: vectorscan::Scratch,
    match_scratch: Scratch,
}

// NOTE: See `matcher.rs` for an explanation why this is an approximation of `impl Matcher for Hyperscan`
impl Hyperscan {
    pub fn id(&self) -> &MatcherId {
        &self.id
    }

    pub fn kind(&self) -> MatcherKind {
        MatcherKind::Hyperscan
    }

    pub fn scan_data<'a, 'b>(
        &'a mut self,
        data: &'b [u8],
    ) -> Result<MatchCursor<'a, 'b>, MatcherError> {
        // Scan the `data`, saving the results scratch. Because of Hyperscan's match semantics, we
        // transform the list of `HsMatch` into a list of `RuleMatch` by "collecting" all the match
        // results directly from Hyperscan into a Vec and then post-process them. This solution
        // was chosen for its simplicity, but comes with the downside that we have no control
        // over telling Hyperscan to halt the scan of some data at a `RuleMatch` boundary.
        self.scan_to_scratch_mut(data)?;

        Ok(MatchCursor::new(
            self.match_scratch.buffers().iter(),
            self.patterns.iter_mut(),
            data,
        ))
    }
}

impl Hyperscan {
    pub fn new(id: MatcherId, pattern_set: PatternSet) -> Self {
        let hs_scratch = vectorscan::Scratch::try_new_for(pattern_set.database())
            .expect("should be able to create hyperscan scratch");
        let (database, patterns) = pattern_set.into_parts();
        let match_scratch = Scratch::new(patterns.len());

        // We rely on the `PatternSet` being sorted, with each `NamedPattern`'s Hyperscan id equal
        // to its offset. This is the default state from the `PatternSetBuilder`, however we also
        // guard this here via panic, as the logic would be completely wrong if this wasn't the case.
        assert!(patterns
            .iter()
            .enumerate()
            .map(|(i, pat)| i == pat.inner().hs().id() as usize)
            .all(|predicate| predicate));

        Self {
            id,
            database,
            patterns,
            match_scratch,
            hs_scratch,
        }
    }

    /// Scans the given `data`, storing the results in the internal scratch buffer.
    fn scan_to_scratch_mut(&mut self, data: &[u8]) -> Result<ScanStatus, MatcherError> {
        let mut scratch = self.match_scratch.get_mut();

        self.database
            .scan(
                &mut self.hs_scratch,
                data,
                Box::new(|hs_match| {
                    // TODO: Add logic to implement a scan timeout
                    scratch.push(hs_match);
                    ControlFlow::Continue(())
                }),
            )
            .map_err(|err| MatcherError::Scan {
                matcher_id: "hyperscan",
                err: Box::new(err),
            })
    }
}

/// A cursor for iterating over the results of a scan.
#[derive(Debug)]
pub struct MatchCursor<'a, 'b> {
    matches_iter: Iter<'a, Vec<HsMatch>>,
    patterns_iter: IterMut<'a, NamedPattern>,
    data: &'b [u8],
    current_mappers_iter: Option<IterWithMetadata<'a, 'b>>,
}

/// A struct holding an along with additional owned metadata relevant to the [`NamedPattern`].
#[derive(Debug)]
struct IterWithMetadata<'a, 'b> {
    pattern_name: Arc<str>,
    named_lookup: Option<Arc<Vec<Option<String>>>>,
    iter: MatchIter<'a, 'b>,
}

impl FusedIterator for MatchCursor<'_, '_> {}

impl<'b> Iterator for MatchCursor<'_, 'b> {
    type Item = PatternMatch<'b>;

    /// This iterator performs a flat map.
    ///
    /// For each pattern:
    /// 1. All [`HsMatch`] present are transformed into [`CaptureSlots`]. The true start of the match
    ///    is calculated, and captures are applied.
    ///    Under the hood, this is a flat map, because not every [`HsMatch`] corresponds with a "true" match.
    /// 2. This iterator transforms the [`CaptureSlots`] into a [`PatternMatch`]
    ///
    /// The result is a continuous stream of [`PatternMatch`], grouped and sorted by Hyperscan [`PatternId`](vectorscan::scan::PatternId)
    /// ascending. Within this grouping, the matches are always sorted by the end byte ascending.
    ///
    /// For example:
    /// ```text
    /// PatternId(1): [(0, 10), (0, 25)]
    /// PatternId(2): []
    /// PatternId(3): [(0, 15), (0, 60), (0, 95)]
    /// PatternId(4): [(0, 33)]
    /// ```
    ///
    /// Would result in a [`FusedIterator`] yielding:
    /// ```text
    /// Some((1, (5, 10)))
    /// Some((1, (20, 25)))
    /// Some((3, (0, 15)))
    /// Some((3, (45, 60)))
    /// Some((3, (80. 95)))
    /// Some((4, (30, 33)))
    /// None
    /// ...
    /// ```
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(IterWithMetadata {
                ref pattern_name,
                ref named_lookup,
                iter,
            }) = &mut self.current_mappers_iter
            {
                if let Some(capture_slots) = iter.next() {
                    let named_lookup = named_lookup
                        .as_ref()
                        .map(|lookup_arc| Arc::clone(lookup_arc));
                    let rule_match = PatternMatch {
                        pattern_id: Arc::clone(pattern_name),
                        full_data: self.data,
                        captures: Captures::new(named_lookup, capture_slots),
                    };

                    return Some(rule_match);
                }
            }

            // Increment both iterators to keep them in sync
            match (self.patterns_iter.next(), self.matches_iter.next()) {
                (Some(pattern), Some(hs_matches)) => {
                    let pattern_name = Arc::clone(&pattern.to_name_arc());
                    let named_lookup = pattern
                        .inner()
                        .regex()
                        .and_then(|regex| regex.to_named_lookup_arc());
                    let next_iter = pattern.inner_mut().transform(hs_matches, self.data);
                    self.current_mappers_iter.replace(IterWithMetadata {
                        pattern_name,
                        named_lookup,
                        iter: next_iter,
                    });
                }
                (None, None) => return None,
                // These cases are impossible because [`Hyperscan`] enforces that these iterators
                // have the same length.
                (Some(_), None) | (None, Some(_)) => unreachable!(),
            }
        }
    }
}

impl<'a, 'b> MatchCursor<'a, 'b> {
    pub fn new(
        matches_iter: Iter<'a, Vec<HsMatch>>,
        patterns_iter: IterMut<'a, NamedPattern>,
        data: &'b [u8],
    ) -> MatchCursor<'a, 'b> {
        Self {
            matches_iter,
            patterns_iter,
            data,
            current_mappers_iter: None,
        }
    }
}

#[rustfmt::skip]
#[cfg(test)]
mod tests {
    use super::{MatchCursor, Scratch};
    use crate::matcher::hyperscan::{Hyperscan, PatternSet};
    use std::borrow::Cow;
    use std::sync::Arc;
    use vectorscan::scan::PatternId;
    use vectorscan::HsMatch;

    /// Creates a Vec of [`HsMatch`] from tuples of (pattern_id, end_byte)
    fn hs_matches(matches: &[(u32, usize)]) -> Vec<HsMatch> {
        matches
            .iter()
            .map(|&(pattern_id, end_byte)| HsMatch::new(pattern_id, 0, end_byte))
            .collect::<Vec<_>>()
    }

    fn p_set(patterns: &[(&str, &str)]) -> PatternSet {
        let mut set = PatternSet::new();
        for &(name, expression) in patterns {
            let hs_pattern = vectorscan::Pattern::new(expression).try_build().unwrap();
            set = set.pattern((Arc::from(name), hs_pattern));
        }
        set.try_compile().unwrap()
    }

    /// Converts a flat vector of [`HsMatch`] into the jagged array that [`MatchCursor`] requires.
    /// This is done on-the-fly by [`Scratch`], but we need to replicate this behavior in test.
    fn as_jagged(mut hs_matches: Vec<HsMatch>) -> Vec<Vec<HsMatch>> {
        hs_matches.sort_by_key(|hs_match| (hs_match.pattern_id().0, hs_match.end()));
        let mut chunked = Vec::<Vec<HsMatch>>::new();
        // Initialize each sub-vec
        for _ in 0..(1 + hs_matches.last().unwrap().pattern_id().0) {
            chunked.push(Vec::new())
        }
        // Populate the sub-vecs
        for hs_match in hs_matches.into_iter() {
            chunked[hs_match.pattern_id().0 as usize].push(hs_match);
        }
        chunked
    }

    /// Cursor should yield the underlying patterns, ordered by the internal [`PatternId`] ascending,
    /// not the user-provided pattern id.
    #[test]
    fn cursor_ascending() {
        let haystack = "aaaa--bbb--ccc---aaaa-bb-bbb--ddd";
        let pattern_set = p_set(&[("0", "(a{2})+"), ("1", "eee"), ("2", "bb"), ("3", "ddd"), ("4", "ccc")]);
        let hs_matches = hs_matches(&[
            (0, 2), (0, 3), (0, 4),
            (2, 8), (2, 9),
            (4, 14),
            (0, 19), (0, 20), (0, 21),
            (2, 24), (2, 27), (2, 28),
            (3, 33),
        ]);
        let hs_matches = as_jagged(hs_matches);
        let (_, mut patterns) = pattern_set.into_parts();

        let mut cursor = MatchCursor::new(hs_matches.iter(), patterns.iter_mut(), haystack.as_bytes());

        assert_eq!(cursor.next().map(|pm| pm.pattern_id), Some("0".into()));
        assert_eq!(cursor.next().map(|pm| pm.pattern_id), Some("0".into()));
        assert_eq!(cursor.next().map(|pm| pm.pattern_id), Some("2".into()));
        assert_eq!(cursor.next().map(|pm| pm.pattern_id), Some("2".into()));
        assert_eq!(cursor.next().map(|pm| pm.pattern_id), Some("2".into()));
        assert_eq!(cursor.next().map(|pm| pm.pattern_id), Some("3".into()));
        assert_eq!(cursor.next().map(|pm| pm.pattern_id), Some("4".into()));
        assert_eq!(cursor.next().map(|pm| pm.pattern_id), None);
    }

    /// Cursor should skip empty Vecs without returning `None`.
    #[test]
    fn cursor_skips_empty() {
        let haystack = "aaa---111---ccc";
        let pattern_set = p_set(&[("0", "aaa"), ("1", "bbb"), ("2", "ccc")]);

        let hs_matches = vec![
            hs_matches(&[(0, 3)]),
            hs_matches(&[]),
            hs_matches(&[(2, 15)]),
        ];

        let (_, mut patterns) = pattern_set.into_parts();
        let mut cursor = MatchCursor::new(hs_matches.iter(), patterns.iter_mut(), haystack.as_bytes());

        assert_eq!(cursor.next().map(|pm| pm.pattern_id), Some("0".into()));
        // Even though "1" was empty, the iterator should skip it and not return `None`.
        assert_eq!(cursor.next().map(|pm| pm.pattern_id), Some("2".into()));
        assert_eq!(cursor.next().map(|pm| pm.pattern_id), None);
    }

    /// The Cursor returns the user-provided pattern name instead of an internal [`PatternId`]
    #[test]
    fn pattern_matches_have_correct_id() {
        let haystack = "aaa---bbb---ccc";
        let pattern_set = p_set(&[("z-name", "aaa"), ("x-name", "bbb"), ("y-name", "ccc")]);

        let hs_matches = vec![
            hs_matches(&[(0, 3)]),
            hs_matches(&[(1, 9)]),
            hs_matches(&[(2, 15)]),
        ];

        let (_, mut patterns) = pattern_set.into_parts();
        let mut cursor = MatchCursor::new(hs_matches.iter(), patterns.iter_mut(), haystack.as_bytes());

        // The cursor should iterate by internal (numeric) pattern id, not the user-provided string.
        assert_eq!(cursor.next().map(|pm| pm.pattern_id), Some("z-name".into()));
        assert_eq!(cursor.next().map(|pm| pm.pattern_id), Some("x-name".into()));
        assert_eq!(cursor.next().map(|pm| pm.pattern_id), Some("y-name".into()));
        assert_eq!(cursor.next().map(|pm| pm.pattern_id), None);
    }

    /// Capture groups can be looked up by name or index.
    #[test]
    fn regex_capture_groups_lookup() {
        let haystack = "----abc--def---ghi---";
        let pattern = vectorscan::Pattern::new("-+(?<foo>abc)-+(?<bar>def)-+(?<baz>ghi)").try_build().unwrap();
        let pattern_set = PatternSet::new().pattern(("name-a".into(), pattern)).try_compile().unwrap();

        let mut hyperscan = Hyperscan::new("hs-1".into(), pattern_set);
        let mut cursor = hyperscan.scan_data(haystack.as_bytes()).unwrap();

        let pattern_match = cursor.next().unwrap();
        assert_eq!(pattern_match.captures.name("foo").map(|c| c.to_str_lossy()), Some(Cow::Borrowed("abc")));
        assert_eq!(pattern_match.captures.name("bar").map(|c| c.to_str_lossy()), Some(Cow::Borrowed("def")));
        assert_eq!(pattern_match.captures.name("baz").map(|c| c.to_str_lossy()), Some(Cow::Borrowed("ghi")));

        assert_eq!(pattern_match.captures.get(0).map(|c| c.to_str_lossy()), Some(Cow::Borrowed("----abc--def---ghi")));
        assert_eq!(pattern_match.captures.get(1).map(|c| c.to_str_lossy()), Some(Cow::Borrowed("abc")));
        assert_eq!(pattern_match.captures.get(2).map(|c| c.to_str_lossy()), Some(Cow::Borrowed("def")));
        assert_eq!(pattern_match.captures.get(3).map(|c| c.to_str_lossy()), Some(Cow::Borrowed("ghi")));
    }

    /// A Regex without captures has a capture group that only contains the entire expression, at index 0.
    #[test]
    fn regex_one_capture() {
        let haystack = "----abcabc----";
        let pattern = vectorscan::Pattern::new("(?:abc)+").try_build().unwrap();
        let pattern_set = PatternSet::new().pattern(("name-a".into(), pattern)).try_compile().unwrap();

        let mut hyperscan = Hyperscan::new("hs-1".into(), pattern_set);
        let mut cursor = hyperscan.scan_data(haystack.as_bytes()).unwrap();

        let pattern_match = cursor.next().unwrap();
        assert!(pattern_match.captures.name_slots().is_none());
        assert_eq!(pattern_match.captures.get(0).map(|c| c.to_str_lossy()), Some(Cow::Borrowed("abcabc")));
        assert!(pattern_match.captures.get(1).is_none());
    }

    /// A Literal's capture group only contains the entire expression, at index 0.
    #[test]
    fn literal_one_capture() {
        let haystack = "----abcabc----";
        let pattern = vectorscan::Pattern::new("abc").literal(true).try_build().unwrap();
        let pattern_set = PatternSet::new().pattern(("name-a".into(), pattern)).try_compile().unwrap();

        let mut hyperscan = Hyperscan::new("hs-1".into(), pattern_set);
        let mut cursor = hyperscan.scan_data(haystack.as_bytes()).unwrap();

        let pattern_match = cursor.next().unwrap();
        assert!(pattern_match.captures.name_slots().is_none());
        assert_eq!(pattern_match.captures.get(0).map(|c| c.to_str_lossy()), Some(Cow::Borrowed("abc")));
        assert!(pattern_match.captures.get(1).is_none());
    }
}
