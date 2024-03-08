// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::common::ByteSpan;
use bstr::{BStr, ByteSlice};
use std::borrow::Cow;
use std::iter::{Enumerate, FusedIterator};
use std::slice::Iter;
use std::sync::Arc;

/// A list of potentially named captures.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Captures<'b> {
    name_slots: Option<Arc<Vec<Option<String>>>>,
    capture_slots: CaptureSlots<'b>,
}

impl<'b> Captures<'b> {
    /// Creates a new [`Captures`] from a `name_slots` and `capture_slots`.
    pub fn new(
        name_slots: Option<Arc<Vec<Option<String>>>>,
        capture_slots: CaptureSlots<'b>,
    ) -> Captures<'b> {
        // Captures is often created in a hot-loop, so we can get away with only checking this
        // invariant in debug mode.
        debug_assert!(name_slots
            .as_ref()
            .map(|name_slots| name_slots.len() == capture_slots.len())
            .unwrap_or(true));
        Self {
            name_slots,
            capture_slots,
        }
    }

    /// Returns the capture names if they exist.
    pub fn name_slots(&self) -> Option<&[Option<String>]> {
        self.name_slots.as_ref().map(|vec| vec.as_slice())
    }
}

impl<'a, 'b> IntoIterator for &'a Captures<'b> {
    type Item = (Option<&'a str>, Option<Capture<'b>>);
    type IntoIter = CapturesIter<'a, 'b>;

    fn into_iter(self) -> Self::IntoIter {
        CapturesIter {
            names: self.name_slots.as_ref(),
            captures: self.capture_slots.0.iter().enumerate(),
        }
    }
}

#[derive(Debug)]
pub struct CapturesIter<'a, 'b> {
    names: Option<&'a Arc<Vec<Option<String>>>>,
    captures: Enumerate<Iter<'a, Option<Capture<'b>>>>,
}

impl<'a, 'b> ExactSizeIterator for CapturesIter<'a, 'b> {}
impl<'a, 'b> FusedIterator for CapturesIter<'a, 'b> {}

impl<'a, 'b> Iterator for CapturesIter<'a, 'b> {
    type Item = (Option<&'a str>, Option<Capture<'b>>);

    fn next(&mut self) -> Option<Self::Item> {
        let (idx, capture) = self.captures.next()?;
        let name = self
            .names
            .map(|vec| {
                vec.get(idx)
                    .expect("names should have exact length of captures")
                    .as_ref()
                    .map(|name| name.as_str())
            })
            .unwrap_or(None);
        Some((name, capture.as_ref().copied()))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.captures.size_hint()
    }
}

impl<'a> Captures<'a> {
    /// Returns the capture with the given name.
    pub fn name(&self, name: &str) -> Option<Capture<'a>> {
        // Iterate `name_slots` from 1..n, searching for a name match.
        let name_slots = self.name_slots.as_ref()?;
        // Skip the first slot, as it's always None.
        let slot_index = name_slots.as_ref().iter().skip(1).position(|slot| {
            slot.as_ref()
                .is_some_and(|capture_name| name == capture_name.as_str())
        })? + 1;

        self.get(slot_index)
    }

    /// Returns the capture with the given index.
    pub fn get(&self, index: usize) -> Option<Capture<'a>> {
        self.capture_slots.get(index)
    }

    /// Returns a [`Capture`] representing the entire match.
    pub fn entire(&self) -> Capture<'a> {
        self.capture_slots.first()
    }

    pub fn captures_len(&self) -> usize {
        self.capture_slots.0.len()
    }
}

/// Every unique pattern must implement the concept of a "capture", which is a specific byte span
/// within searched data.
///
/// [`CaptureSlots`] is the data structure that holds a list of captures, starting with the
/// entire match as the first element. Thus, this Vec can never be empty.
///
/// Patterns can implement additional captures in the form of sub-slices that are never larger
/// than the entire match. These sub-slices can even be conditional. However, the [`CaptureSlots`]
/// that a pattern generates must always be the same length, even if some captures are not present.
/// That is, `Some("text")` always represents a present capture, while `None` represents a
/// conditional capture that was not present in the searched data.
///
/// Consider the following:
/// ```text
/// Regex: `(abc)-+(def-+)?(ghi)`
/// The CaptureSlots vec will always have 4 members (1 for the entire capture, and 3 possible sub-captures).
/// |  Entire Match   |     fixed 1     |  conditional 2  |     fixed 3      |
///
/// When the pattern is run against the string "abc-def-ghi", the result will be
///
///  |  Entire Match   |     fixed 1     |  conditional 2  |     fixed 3      |
///  | Some(abc-def-ghi)    Some(abc)         Some(def)          Some(ghi)    |
///
///  Whereas, when run against the string "abc-ghi"
///  |  Entire Match   |     fixed 1     |  conditional 2  |     fixed 3      |
///  | Some(abc-ghi)        Some(abc)           None             Some(ghi)    |
/// ```
/// Individual captures do not need to be unique. A regex like "(abc)" will produce a [`CaptureSlots`]
/// with length 2, with indexes 0 and 1 both containing `Some("abc")` upon match.
///
#[derive(Debug, Clone, Eq, PartialEq)]
#[repr(transparent)]
pub struct CaptureSlots<'b>(Vec<Option<Capture<'b>>>);

impl<'b> CaptureSlots<'b> {
    /// Creates a new [`CaptureSlots`] from a list of sub-captures.
    ///
    /// # Panics
    /// Panics is `capture_slots` is empty
    pub fn new(captures: Vec<Option<Capture<'b>>>) -> CaptureSlots<'b> {
        Self(captures)
    }

    /// Creates a new [`CaptureSlots`] with zero sub-captures.
    ///
    /// * `full_data` should be the entire data that was searched.
    /// * `byte_span` should be the capture, which is a slice of the `full_data`.
    ///
    /// # Panics
    /// Panics if `byte_span` has an `end_index` greater than the `full_data`.
    pub fn new_without_captures(full_data: &'b [u8], byte_span: ByteSpan) -> CaptureSlots<'b> {
        let captures = vec![Some(Capture::new_from_data(full_data, byte_span))];
        Self(captures)
    }

    pub fn get(&self, index: usize) -> Option<Capture<'b>> {
        self.0.get(index).copied().flatten()
    }

    /// Returns the first [`Capture`], which represents the entire match.
    pub fn first(&self) -> Capture<'b> {
        self.0
            .first()
            .expect("there should always be at least one element in CaptureSlots")
            .expect("the first element should always be `Some` representing the entire match")
    }

    /// Returns the number of capture slots.
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

/// A byte slice representing a capture, as well as the parent that it was sliced from.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Capture<'b> {
    /// The parent slice, which is a superset of the `captured`
    parent: &'b [u8],
    /// The (subset) slice of bytes that was captured.
    captured: &'b [u8],
}

impl<'b> Capture<'b> {
    /// Creates a new [`Capture`].
    ///
    /// * `full_data` should be the entire data that was searched.
    /// * `byte_span` should be the capture, which is a slice of the `full_data`.
    ///
    /// # Panics
    /// Panics if `byte_span` has an `end_index` greater than the `full_data`.
    pub fn new_from_data(full_data: &'b [u8], byte_span: ByteSpan) -> Capture<'b> {
        let captured = full_data
            .get(byte_span.as_range())
            .expect("byte span of capture should not be greater than data");
        Self {
            parent: full_data,
            captured,
        }
    }

    pub fn as_bytes(&self) -> &'b [u8] {
        self.captured
    }

    pub fn as_str(&self) -> Result<&'b str, std::str::Utf8Error> {
        std::str::from_utf8(self.captured)
    }

    #[allow(clippy::wrong_self_convention)]
    pub fn to_str_lossy(&self) -> Cow<'b, str> {
        BStr::new(self.captured).to_str_lossy()
    }

    #[inline]
    pub fn start(&self) -> usize {
        self.captured.as_ptr() as usize - self.parent.as_ptr() as usize
    }

    #[inline]
    pub fn end(&self) -> usize {
        self.start() + self.captured.len()
    }

    #[inline]
    pub fn byte_span(&self) -> ByteSpan {
        ByteSpan {
            start_index: self.start() as u32,
            end_index: self.end() as u32,
        }
    }

    pub fn parent(&self) -> &'b [u8] {
        self.parent
    }
}

#[cfg(test)]
mod tests {
    use crate::capture::{Capture, CaptureSlots, Captures};
    use crate::common::ByteSpan;
    use std::sync::Arc;

    const HAYSTACK: &str = "abc---def---ghi";
    fn cap(start: usize, end: usize) -> Option<Capture<'static>> {
        Some(Capture::new_from_data(
            HAYSTACK.as_bytes(),
            ByteSpan::new(start, end),
        ))
    }
    fn names(names: &[Option<&str>]) -> Arc<Vec<Option<String>>> {
        let vec = names
            .iter()
            .map(|opt| opt.map(|str| str.to_string()))
            .collect::<Vec<_>>();
        Arc::from(vec)
    }

    #[test]
    fn captures_iter_no_names() {
        let captures = Captures::new(
            None,
            CaptureSlots::new(vec![cap(0, 15), cap(0, 3), cap(6, 9), cap(12, 15)]),
        );
        let mut iter = captures.into_iter();
        assert_eq!(iter.next(), Some((None, cap(0, 15))));
        assert_eq!(iter.next(), Some((None, cap(0, 3))));
        assert_eq!(iter.next(), Some((None, cap(6, 9))));
        assert_eq!(iter.next(), Some((None, cap(12, 15))));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn captures_iter_all_names() {
        let captures = Captures::new(
            Some(names(&[None, Some("cap_a"), Some("cap_b"), Some("cap_c")])),
            CaptureSlots::new(vec![cap(0, 15), cap(0, 3), cap(6, 9), cap(12, 15)]),
        );
        let mut iter = captures.into_iter();
        assert_eq!(iter.next(), Some((None, cap(0, 15))));
        assert_eq!(iter.next(), Some((Some("cap_a"), cap(0, 3))));
        assert_eq!(iter.next(), Some((Some("cap_b"), cap(6, 9))));
        assert_eq!(iter.next(), Some((Some("cap_c"), cap(12, 15))));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn captures_iter_sparse_names() {
        let captures = Captures::new(
            Some(names(&[None, Some("cap_a"), None, Some("cap_c")])),
            CaptureSlots::new(vec![cap(0, 15), cap(0, 3), cap(6, 9), cap(12, 15)]),
        );
        let mut iter = captures.into_iter();
        assert_eq!(iter.next(), Some((None, cap(0, 15))));
        assert_eq!(iter.next(), Some((Some("cap_a"), cap(0, 3))));
        assert_eq!(iter.next(), Some((None, cap(6, 9))));
        assert_eq!(iter.next(), Some((Some("cap_c"), cap(12, 15))));
        assert_eq!(iter.next(), None);
    }
}
