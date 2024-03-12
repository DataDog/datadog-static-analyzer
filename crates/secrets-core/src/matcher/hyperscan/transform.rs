// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::capture::CaptureSlots;
use crate::common::ByteSpan;
use crate::matcher::hyperscan::pattern::{Pattern, PatternWidth};
use std::iter::FusedIterator;
use std::slice::Iter;
use vectorscan::HsMatch;

impl Pattern {
    /// Creates an iterator that transforms a list of [`HsMatch`] into a list of [`CaptureSlots`].
    ///
    /// Hyperscan uses streaming semantics, and so for the following:
    /// * Pattern:  `aaaa`
    /// * Haystack: `aaaaaaaaaa`
    ///
    /// By default, Hyperscan will report seven [`HsMatch`] structs:
    /// ```text
    /// aaaaaaaaaa
    /// aaaa         (0,  4)
    ///  aaaa        (0,  5)
    ///   aaaa       (0,  6)
    ///    aaaa      (0,  7)
    ///     aaaa     (0,  8)
    ///      aaaa    (0,  9)
    ///       aaaa   (0, 10)
    /// ```
    ///
    /// `transform` creates a performant iterator that flat maps a sorted list of [`HsMatch`] to implement
    /// the "standard" regex semantics: non-overlapping, left-precedence matches, including captures.
    /// ```text
    /// aaaaaaaaaa
    /// aaaa         (0, 4)
    ///  ----
    ///   ----
    ///    ----
    ///     aaaa     (4, 8)
    ///      ----
    ///       ----
    /// ```
    pub fn transform<'a, 'b>(
        &'a mut self,
        matches: &'a [HsMatch],
        source: &'b [u8],
    ) -> MatchIter<'a, 'b> {
        MatchIter::new(matches, source, self)
    }
}

#[derive(Debug)]
pub struct MatchIter<'a, 's> {
    match_iter: Iter<'a, HsMatch>,
    source: &'s [u8],
    pattern: &'a mut Pattern,

    window_start: usize,
    window_end: usize,
}

impl<'a, 's> MatchIter<'a, 's> {
    pub fn new(
        matches: &'a [HsMatch],
        source: &'s [u8],
        pattern: &'a mut Pattern,
    ) -> MatchIter<'a, 's> {
        let (window_start, window_end) = match pattern.width() {
            PatternWidth::Fixed(_) => {
                // The window is not used for fixed width
                (0_usize, 0_usize)
            }
            PatternWidth::Variable { max, .. } => {
                let last_end = matches.last().map(|hsm| hsm.end()).unwrap_or(0);
                if let Some(max_width) = max {
                    // Position the left window boundary at the first byte that could possibly be in a pattern.
                    let first_start = matches
                        .first()
                        .map(|hs_match| hs_match.start().saturating_sub(max_width))
                        .unwrap_or(0);
                    (first_start, last_end)
                } else {
                    // An unbounded pattern must start at 0
                    (0_usize, last_end)
                }
            }
        };
        Self {
            match_iter: matches.iter(),
            source,
            pattern,
            window_start,
            window_end,
        }
    }
}

impl FusedIterator for MatchIter<'_, '_> {}

impl<'s> Iterator for MatchIter<'_, 's> {
    type Item = CaptureSlots<'s>;

    fn next(&mut self) -> Option<Self::Item> {
        for hs_match in self.match_iter.by_ref() {
            let capture_slots = match self.pattern.width() {
                PatternWidth::Fixed(width) => {
                    // This should never underflow, as Hyperscan won't send an invalid match.
                    let start = hs_match.end() - width;
                    // If two matches intersect, prefer the left-most match.
                    if start < self.window_start {
                        continue;
                    }

                    let raw_captures = if let Some(regex) = self.pattern.regex_mut() {
                        let capture_slots = regex
                            .captures_read_at(self.source, start, hs_match.end())
                            // We `expect` the Option because if this doesn't match, there is a problem
                            // in either pcre2 or hyperscan's reported offsets that warrants a panic.
                            .expect("regex for fixed-width capture should match");
                        // This match should have occurred exactly at the end index Hyperscan reported.
                        debug_assert_eq!(
                            capture_slots.first().end(),
                            hs_match.end(),
                            "wrong pcre2 end index"
                        );
                        capture_slots
                    } else {
                        // If there isn't a regex, there are no captures
                        CaptureSlots::new_without_captures(
                            self.source,
                            ByteSpan::new(start, hs_match.end()),
                        )
                    };

                    self.window_start = hs_match.end();
                    raw_captures
                }
                PatternWidth::Variable {
                    min: min_width,
                    max: max_width,
                } => {
                    // For a match to be inside the window, its end minus its min width needs to be at least `window_start`.
                    // The subtraction should never underflow, as Hyperscan won't send an invalid match.
                    if hs_match.end() - min_width < self.window_start {
                        continue;
                    }
                    // If there is a known max-width, we can further constrain the window to reduce the search space.
                    // This is particularly effective if there are large gaps between matches.
                    let start = self.window_start;
                    let start = max_width.map_or(start, |max_width| {
                        start.max(hs_match.end().saturating_sub(max_width))
                    });

                    // We use the window's right boundary (which is the end of the last capture) because we want to
                    // allow for greedy captures up until the final capture.
                    let regex = self
                        .pattern
                        .regex_mut()
                        .expect("variable width pattern should have regex");
                    let capture_slots = regex
                        .captures_read_at(self.source, start, self.window_end)
                        // We `expect` the Option because if this doesn't match, there is a problem
                        // in either pcre2 or hyperscan's reported offsets that warrants a panic.
                        .expect("regex for variable-width capture should match");

                    // Slide the window so all future regex executions occur after this match.
                    self.window_start = capture_slots.first().end();
                    capture_slots
                }
            };
            return Some(capture_slots);
        }
        None
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let (min_width, max_width) = match self.pattern.width() {
            PatternWidth::Fixed(width) => (width, Some(width)),
            // We have to assume each capture is the minimum width it could be in order to not under-estimate the hint.
            PatternWidth::Variable { min, max } => (min, max),
        };

        // The underlying iterator is an ExactSizeIterator, where min and max will be the number of
        // elements left in the slice. Both are over-estimates of the true (min, max).
        //
        // To calculate the lowest possible minimum, we assume we're currently at the right-most
        // bound of an actual match (i.e. ending the previous match), and that the pattern is
        // the widest it can possibly be.
        //
        // Similarly, to calculate the highest possible maximum, we assume we're currently at the
        // left-most bound of an actual match (i.e. starting a match), and that the pattern is the
        // smallest it can possibly be.
        //
        // For example, for the following:
        // Pattern: `aaa{0,6}` (min_width: 2, max_width: 8)
        // Text   : `aaaaaaaaaaaaaaaaa`
        //                 *
        // Hypothetical right-most bound and max pattern max width:
        // Text   : `aaaaaaaaaaaaaaaaa`
        //                 *
        //           |-----||      |
        // There is at least 1 more match (versus "at least 10 more matches").
        //
        // Hypothetical left-most bound and min pattern width:
        // Text   : `aaaaaaaaaaaaaaaaa`
        //                 *
        //                 ||
        //                   ||
        //                     ||
        //                       ||
        //                         ||
        // There are at most 5 more matches (versus "at most 10 more matches").

        let min_required = if let Some(max_width) = max_width {
            self.window_end.saturating_sub(self.window_start + 1) / max_width
        } else {
            0
        };
        let lower = usize::min(self.match_iter.size_hint().0, min_required);

        let max_possible = (self.window_end - self.window_start) / min_width;
        let upper = if let Some(hinted_upper) = self.match_iter.size_hint().1 {
            usize::min(hinted_upper, max_possible)
        } else {
            max_possible
        };

        (lower, Some(upper))
    }
}

#[rustfmt::skip]
#[cfg(test)]
mod tests {
    use crate::capture::{Capture, CaptureSlots};
    use crate::common::ByteSpan;
    use crate::matcher::hyperscan::pattern_set::PatternWithId;
    use crate::matcher::hyperscan::PatternSet;
    use vectorscan::{HsMatch, Scratch};

    /// Generates a vec of [`Capture`] given a reference to a source text &str and byte spans.
    fn cap_slots<'b>(text: &'b str, captures: &[Option<(usize, usize)>]) -> CaptureSlots<'b> {
        let slots = captures.iter().map(|opt|
            opt.as_ref().map(|&span| {
                let byte_span = ByteSpan::new(span.0, span.1);
                Capture::new_from_data(text.as_bytes(), byte_span)
            })
        ).collect::<Vec<_>>();
        CaptureSlots::new(slots)
    }

    fn scan(expression: &str, haystack: &str, is_literal: bool) -> (Vec<HsMatch>, PatternWithId) {
        let pattern = vectorscan::compiler::Pattern::new(expression)
            .literal(is_literal)
            .try_build()
            .unwrap();
        let pattern_set = PatternSet::new(0.into())
            .pattern(pattern)
            .try_compile()
            .unwrap();
        let mut scratch = Scratch::try_new_for(pattern_set.database()).unwrap();
        let matches = pattern_set.database().scan_collect(&mut scratch, haystack);

        let pattern = pattern_set.get(0.into()).unwrap().clone();
        (matches.unwrap(), pattern)
    }

    #[test]
    fn fixed_width_regex_captures() {
        // NOTE: This is a fake key generated specifically for this test.
        let haystack = "(FAKE_KEY)----abc_5vuUNLBbdSYYHojHZTL6x7XaDBsS294Q9eQb----";

        for expression in [
            "([a-z]{2})([[:lower:]])_([a-zA-Z0-9]{30})([a-zA-Z0-9]{6})",
            "(?<company_id>[a-z]{2})(?<kind>[[:lower:]])_(?<inner>[a-zA-Z0-9]{30})(?<checksum>[a-zA-Z0-9]{6})",
        ] {
            let (matches, mut pattern) = scan(expression, haystack, false);
            assert_eq!(matches.len(), 1);
            let expected = cap_slots(haystack, &[Some((14, 54)), Some((14, 16)), Some((16, 17)), Some((18, 48)), Some((48, 54))]);

            let mut captures = pattern.inner_mut().transform(&matches, haystack.as_bytes());
            assert_eq!(captures.next(), Some(expected));
            assert_eq!(captures.next(), None);
        }
    }

    #[test]
    fn fixed_width_literal_captures() {
        let haystack = "aaaaaaaaaaaaa-aaaaaaa";
        let (matches, mut pattern) = scan("aaaaa", haystack, true);
        assert_eq!(matches.len(), 12);

        let mut captures = pattern.inner_mut().transform(&matches, haystack.as_bytes());
        assert_eq!(captures.next(), Some(cap_slots(haystack, &[Some((0, 5))])));
        assert_eq!(captures.next(), Some(cap_slots(haystack, &[Some((5, 10))])));
        assert_eq!(captures.next(), Some(cap_slots(haystack,&[Some((14, 19))])));
        assert_eq!(captures.next(), None);
    }

    /// Variable-width regex captures respect left-to-right greedy semantics
    #[test]
    fn variable_width_regex_captures() {
        let haystack = "abc--abcabc-----";
        let (matches, mut pattern) = scan("a(bc-{0,3})", haystack, false);
        assert_eq!(matches.len(), 8);

        let mut captures = pattern.inner_mut().transform(&matches, haystack.as_bytes());
        assert_eq!(captures.next(), Some(cap_slots(haystack, &[Some((0, 5)), Some((1, 5))])));
        assert_eq!(captures.next(), Some(cap_slots(haystack, &[Some((5, 8)), Some((6, 8))])));
        assert_eq!(captures.next(), Some(cap_slots(haystack, &[Some((8, 14)), Some((9, 14))])));
        assert_eq!(captures.next(), None);
    }

    /// A greedy capture takes as much as it can, starting from the left.
    #[test]
    fn greedy_leftmost() {
        // While a typical secret-detection rule will not have degenerate corner-case overlaps like this,
        // we should still have correct behavior here.
        let haystack = "aaaaaaaaaa";
        let (matches, mut pattern) = scan("a{2,6}", haystack, false);
        assert_eq!(matches.len(), 9);
        let mut captures = pattern.inner_mut().transform(&matches, haystack.as_bytes());
        assert_eq!(captures.next(), Some(cap_slots(haystack, &[Some((0, 6))])));
        assert_eq!(captures.next(), Some(cap_slots(haystack, &[Some((6, 10))])));
        assert_eq!(captures.next(), None);

        let haystack = "aaaaaaaaaab";
        let (matches, mut pattern) = scan("a+b?", haystack, false);
        assert_eq!(matches.len(), 11);
        let mut captures = pattern.inner_mut().transform(&matches, haystack.as_bytes());
        assert_eq!(captures.next(), Some(cap_slots(haystack, &[Some((0, 11))])));
        assert_eq!(captures.next(), None);
    }

    /// Capture groups can be `None` if they are conditional in the regex.
    #[test]
    fn conditional_capture_groups() {
        // Capture groups can be `None`
        let haystack = "abc---abc";
        let (matches, mut pattern) = scan("abc-+(1)?-+abc", haystack, false);
        assert_eq!(matches.len(), 1);
        let mut captures = pattern.inner_mut().transform(&matches, haystack.as_bytes());
        assert_eq!(captures.next(), Some(cap_slots(haystack, &[Some((0, 9)), None])));
        assert_eq!(captures.next(), None);
    }
}
