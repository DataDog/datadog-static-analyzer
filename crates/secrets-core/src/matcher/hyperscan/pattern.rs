// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::capture::{Capture, CaptureSlots};
use crate::common::ByteSpan;
use pcre2::bytes::{Regex, RegexBuilder};
use std::sync::Arc;
use vectorscan::compiler::pattern::{Expression, Flags};
use vectorscan::scan::PatternId;

/// An augmenting abstraction over a [`vectorscan::Pattern`] that adds a backing [`Regex`].
///
/// Patterns are categorized as:
/// * `Regex`: Any pattern that uses regex.
/// * `Literal`: Any pattern that is an exact, literal string.
#[derive(Debug, Clone)]
pub struct Pattern {
    hs_pattern: vectorscan::Pattern,
    kind: PatternKind,
    width: PatternWidth,
}

impl Pattern {
    pub fn hs(&self) -> &vectorscan::Pattern {
        &self.hs_pattern
    }

    /// Returns the id used by Hyperscan to report a match.
    pub fn hs_id(&self) -> PatternId {
        PatternId(self.hs().id())
    }

    pub fn kind(&self) -> &PatternKind {
        &self.kind
    }

    pub fn regex(&self) -> Option<&InnerRegex> {
        match &self.kind {
            PatternKind::Regex(inner) => Some(inner),
            PatternKind::Literal => None,
        }
    }

    #[inline]
    pub fn regex_mut(&mut self) -> Option<&mut InnerRegex> {
        match &mut self.kind {
            PatternKind::Regex(inner) => Some(inner),
            PatternKind::Literal => None,
        }
    }

    pub fn width(&self) -> PatternWidth {
        self.width
    }
}

/// A thin layer over the min and max width from a [`vectorscan::Pattern`]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum PatternWidth {
    Fixed(usize),
    Variable { min: usize, max: Option<usize> },
}

#[derive(Debug, Clone)]
pub enum PatternKind {
    Regex(InnerRegex),
    Literal,
}

impl PatternKind {
    /// Returns a reference to the [`InnerRegex`] if it exists.
    pub(crate) fn regex(&self) -> Option<&InnerRegex> {
        match &self {
            PatternKind::Regex(inner) => Some(inner),
            PatternKind::Literal => None,
        }
    }

    /// Returns a mutable reference to the [`InnerRegex`] if it exists.
    pub(crate) fn regex_mut(&mut self) -> Option<&mut InnerRegex> {
        match self {
            PatternKind::Regex(inner) => Some(inner),
            PatternKind::Literal => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct InnerRegex {
    regex: Regex,
    /// A mutable scratch space to write regex scan captures into.
    scratch: pcre2::bytes::CaptureLocations,
    /// A Vec of the name for each capture, if it exists. If this option is `Some`, then the regex
    /// is guaranteed to have at least one named capture in the Vec.
    ///
    /// This is stored as a `Vec` instead of a `HashMap<String, usize>`, as the number of named
    /// captures will be small, so iterating the Vec to find a name will be faster than a HashMap lookup.
    named_slots: Option<Arc<Vec<Option<String>>>>,
}

impl InnerRegex {
    pub fn new(regex: Regex) -> Self {
        // Only create a Vec if there are actually capture names. Under the hood, `pcre2::Regex`
        // will use a Vec, even if all captures are unnamed.
        let named_count = regex
            .capture_names()
            .iter()
            .fold(0, |prev, next| prev + next.as_ref().map(|_| 1).unwrap_or(0));

        let named_slots = (named_count > 0).then(|| {
            // We use the same internal representation as `pcre2::Regex`, so we clone their Vec.
            let cloned = regex.capture_names().to_vec();
            Arc::new(cloned)
        });
        let scratch = regex.capture_locations();

        Self {
            regex,
            scratch,
            named_slots,
        }
    }

    /// Executes the regex against the `subject`, starting at the given offset. The captures are
    /// read into an internal scratch buffer.
    ///
    /// # Panics
    ///
    /// * Panics if the `pcre2` FFI call to the regex engine fails.
    pub fn captures_read_at<'s>(
        &mut self,
        data: &'s [u8],
        start: usize,
        end: usize,
    ) -> Option<CaptureSlots<'s>> {
        let pcre2_match = self
            .regex
            .captures_read_at(&mut self.scratch, &data[0..end], start)
            .expect("pcre2 should not error when scanning")?;

        // The regex wrote to its scratch, so iterate through it via the FFI call wrapper.
        let capture_slots = (0..self.regex.captures_len())
            .map(|idx| {
                self.scratch.get(idx).map(|(start, end)| {
                    let byte_span = ByteSpan::new(start, end);
                    Capture::new_from_data(data, byte_span)
                })
            })
            .collect::<Vec<_>>();

        // Short of a bug in the `pcre2` library, this will always be true:
        debug_assert!(pcre2_match.as_bytes() == capture_slots[0].unwrap().as_bytes());

        Some(CaptureSlots::new(capture_slots))
    }

    /// Returns a reference to a Vec containing all the named captures in order.
    pub fn as_named_lookup_ref(&self) -> Option<&Arc<Vec<Option<String>>>> {
        self.named_slots.as_ref()
    }

    /// Returns an `Option` of the named lookup. If `Some`, the value is the cloned [`Arc`].
    #[inline]
    pub fn to_named_lookup_arc(&self) -> Option<Arc<Vec<Option<String>>>> {
        self.named_slots.clone()
    }
}

impl TryFrom<vectorscan::Pattern> for Pattern {
    type Error = pcre2::Error;

    fn try_from(value: vectorscan::Pattern) -> Result<Self, Self::Error> {
        convert_hs_pattern(value)
    }
}

/// The maximum size of PCRE2's JIT stack, in bytes.
const MAX_JIT_STACK_SIZE: usize = 2_usize.pow(18);

/// Converts a [`vectorscan::Pattern`] to a [`Pattern`]. If required, this generates a backing
/// [`Regex`] that contains the same detection semantics as the Hyperscan pattern, but supports
/// captures and can calculate the start of a match.
fn convert_hs_pattern(hs_pattern: vectorscan::Pattern) -> Result<Pattern, pcre2::Error> {
    let max_width = hs_pattern.info().max_width;
    let min_width = hs_pattern.info().min_width as usize;

    let width = match (max_width, min_width) {
        (vectorscan::compiler::pattern::Width::Unbounded, min) => {
            PatternWidth::Variable { min, max: None }
        }
        (vectorscan::compiler::pattern::Width::Bounded(max), min) => {
            let max = max as usize;
            if max == min {
                PatternWidth::Fixed(max)
            } else {
                PatternWidth::Variable {
                    min,
                    max: Some(max),
                }
            }
        }
    };
    Ok(match hs_pattern.expression() {
        Expression::Literal(_) => Pattern {
            hs_pattern,
            kind: PatternKind::Literal,
            width,
        },
        Expression::Regex(expression) => {
            if hs_pattern.flags().contains(Flags::COMBINATION) {
                todo!("Hyperscan logical combination is not yet supported");
            }
            let regex = RegexBuilder::new()
                .caseless(hs_pattern.flags().contains(Flags::CASELESS))
                .dotall(hs_pattern.flags().contains(Flags::DOTALL))
                .multi_line(hs_pattern.flags().contains(Flags::MULTI_LINE))
                .ucp(hs_pattern.flags().contains(Flags::UCP))
                .utf(hs_pattern.flags().contains(Flags::UTF8))
                .jit_if_available(true)
                .max_jit_stack_size(Some(MAX_JIT_STACK_SIZE))
                .build(expression.as_str())?;
            Pattern {
                hs_pattern,
                kind: PatternKind::Regex(InnerRegex::new(regex)),
                width,
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::{convert_hs_pattern, Pattern, PatternKind};
    use pcre2::bytes::Regex;
    use vectorscan::compiler::pattern::Flags;

    impl Pattern {
        /// Unwraps a reference to the underlying [`Regex`].
        fn rx(&self) -> &Regex {
            &self.regex().map(|r| &r.regex).unwrap()
        }
    }

    /// Constructs a [`vectorscan::Pattern`], optionally configuring it via its [`PatternBuilder`](vectorscan::PatternBuilder).
    macro_rules! pattern_from {
        // Accept an `expression` and, if included, `config_call` tokens to invoke on the `PatternBuilder`
        ($expression:expr $(, $($config_call:tt)*)?) => {{
            vectorscan::Pattern::new($expression)
                $(.$($config_call)*)?
                .try_build()
                .map(|hs_pattern| convert_hs_pattern(hs_pattern).unwrap())
        }};
    }

    /// [`Pattern`] regex should implement numeric captures.
    #[test]
    fn regex_numeric_captures() {
        let pattern = pattern_from!("(abc)(?:def)(ghi)").unwrap();

        let haystack = b"abcdefghi";
        let captures = pattern.rx().captures(haystack).unwrap().unwrap();
        assert_eq!(captures.get(0).unwrap().as_bytes(), haystack);
        assert_eq!(captures.get(1).unwrap().as_bytes(), b"abc");
        assert_eq!(captures.get(2).unwrap().as_bytes(), b"ghi");
        assert_eq!(captures.get(3), None);
    }

    /// [`Pattern`] regex should implement named captures.
    #[test]
    fn regex_named_captures() {
        let pattern = pattern_from!("(?<named_first>abc)(?:def)(?<named_second>ghi)").unwrap();

        let haystack = b"abcdefghi";
        let captures = pattern.rx().captures(haystack).unwrap().unwrap();
        assert_eq!(captures.get(0).unwrap().as_bytes(), haystack);
        assert_eq!(captures.name("named_first").unwrap().as_bytes(), b"abc");
        assert_eq!(captures.name("named_second").unwrap().as_bytes(), b"ghi");
    }

    /// [`Pattern`] regex should match all flag semantics.
    #[test]
    fn regex_preserve_flag_semantics() {
        let pattern = pattern_from!("ABC", flags(Flags::CASELESS)).unwrap();
        assert!(pattern.rx().is_match(b"abc").unwrap());

        let pattern = pattern_from!("abc.def", flags(Flags::DOTALL)).unwrap();
        assert!(pattern.rx().is_match(b"abc\ndef").unwrap());

        let pattern = pattern_from!("^abc\ndef$", flags(Flags::MULTI_LINE)).unwrap();
        let regex = pattern.rx();
        assert!(regex.is_match(b"abc\ndef").unwrap());
        assert!(!regex.is_match(b"abc\ndef123").unwrap());
        assert!(!regex.is_match(b"123abc\ndef").unwrap());

        let pattern = pattern_from!("\\w").unwrap();
        assert!(!pattern.rx().is_match("å".as_bytes()).unwrap());

        let pattern = pattern_from!("\\w", flags(Flags::UTF8 | Flags::UCP)).unwrap();
        assert!(pattern.rx().is_match("å".as_bytes()).unwrap());
    }

    /// [`PatternKind::Literal`] should be created from a [`vectorscan::Pattern`] literal.
    #[test]
    fn literal() {
        let pattern = pattern_from!("(abc)(?:def)(ghi)", literal(true)).unwrap();
        assert!(matches!(pattern.kind, PatternKind::Literal));
    }
}
