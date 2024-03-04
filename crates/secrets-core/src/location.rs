// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::common::ByteSpan;
use bstr::{BStr, ByteSlice};
use std::cell::{Cell, RefCell};
use std::num::NonZeroU32;

/// A one-based point representing a line and column in a string.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub(crate) struct Point {
    pub line: NonZeroU32,
    pub col: NonZeroU32,
}

impl Point {
    /// Creates a new `Point`.
    ///
    /// # Panics
    /// Panics if either `line` or `col` are 0
    pub fn new(line: u32, col: u32) -> Point {
        Self {
            line: NonZeroU32::new(line).unwrap(),
            col: NonZeroU32::new(col).unwrap(),
        }
    }

    /// Returns the line represented by this point.
    #[inline]
    pub fn line(&self) -> usize {
        self.line.get() as usize
    }

    /// Returns the column represented by this point.
    #[inline]
    pub fn col(&self) -> usize {
        self.col.get() as usize
    }
}

impl Default for Point {
    fn default() -> Self {
        Self {
            line: NonZeroU32::new(1).unwrap(),
            col: NonZeroU32::new(1).unwrap(),
        }
    }
}

/// A span of [`Point`]s representing a range of lines and columns in a text.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub(crate) struct PointSpan {
    start: Point,
    end: Point,
}

impl PointSpan {
    pub fn new(start: Point, end: Point) -> Self {
        Self { start, end }
    }

    /// Returns the start of this span.
    #[inline]
    pub fn start(&self) -> Point {
        self.start
    }

    /// Returns the end of this span.
    #[inline]
    pub fn end(&self) -> Point {
        self.end
    }
}

/// A "child" byte slice that has been located inside its "parent", where the [`ByteSpan`] `start_index`
/// is the offset of the child within the parent.
///
/// Note that this struct has no direct knowledge of its parent, only its own relative offset.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct Located<'d> {
    child: &'d [u8],
    byte_span: ByteSpan,
    point_span: PointSpan,
}

impl<'d> Located<'d> {
    #[inline]
    pub fn child(&self) -> &'d [u8] {
        self.child
    }

    #[inline]
    pub fn byte_span(&self) -> ByteSpan {
        self.byte_span
    }

    #[inline]
    pub fn point_span(&self) -> PointSpan {
        self.point_span
    }
}

/// The surrounding context (bytes) of a byte slice.
///
/// ```text
/// let mut keys = BTreeMap::new();                                                                      // |
/// let key: Hmac<Sha256> = Hmac::new_from_slice("89fa3c91a1c4b814c44fcaea4d9b0b7b9fcf114f".as_bytes()); // |  surrounding
/// //                                            ________________________________________
/// //                                                             child
/// let request = Request {                                                                              // |
/// ```
///
/// For string-like types, this will represent the preceding and following lines.
///
/// Note that this does not contain a reference to the actual parent. The caller must track that separately.
#[derive(Debug, Clone)]
pub struct Context<'d> {
    surrounding: Located<'d>,
    child: Located<'d>,
}

impl<'d> Context<'d> {
    /// Returns the surrounding lines for the child.
    #[inline]
    pub fn surrounding(&self) -> Located<'d> {
        self.surrounding
    }

    /// Returns the located child.
    #[inline]
    pub fn child(&self) -> Located<'d> {
        self.child
    }
}

/// `PointLocator` takes input data and caches information about line and column offsets.
///
/// Internally, it uses binary search for `O(log n)` time complexity to identify a line,
/// and standard (grapheme-aware) iteration for `O(m)` time complexity to identify a column.
///
/// Traversing the data to find newlines is done lazily, and the result is cached up to
/// the highest requested byte offset.
pub struct PointLocator<'d> {
    data: &'d [u8],
    scanned_up_to: Cell<usize>,
    /// A vector of byte offsets, where each entry corresponds to the start byte of a line.
    // Interior mutability via `RefCell` here is a good way to lazily compute this while
    // having this kind of caching be opaque to the caller.
    line_offsets: RefCell<Vec<usize>>,
}

pub type LineNumber = usize;

impl<'d> PointLocator<'d> {
    pub fn new(data: &'d [u8]) -> PointLocator<'d> {
        Self {
            data,
            scanned_up_to: Cell::new(0),
            line_offsets: RefCell::new(vec![0]),
        }
    }

    /// Returns a [`PointSpan`] for the underlying data, given a [`ByteSpan`].
    ///
    /// # Panics
    /// Panics if `byte_span` is out-of-bounds of the underlying data.
    pub fn get_point_span(&self, byte_span: ByteSpan) -> PointSpan {
        let end = self.search_for_point(byte_span.end_index as usize);
        let start = self.search_for_point(byte_span.start_index as usize);
        PointSpan { start, end }
    }

    /// Returns a [`Point`] for the underlying data, given a byte offset.
    ///
    /// # Panics
    /// Panics if `byte_span` is out-of-bounds of the underlying data.
    pub fn get_point(&self, byte_offset: usize) -> Point {
        self.search_for_point(byte_offset)
    }

    /// Extracts a [`Context`] from the underlying data, given a [`ByteSpan`].
    ///
    /// # Panics
    /// Panics if `byte_span` is out-of-bounds of the underlying data.
    pub fn extract_context(&self, byte_span: ByteSpan) -> Context<'d> {
        let child_point_span = self.get_point_span(byte_span);
        let child = Located {
            child: &self.data[byte_span.as_range()],
            byte_span,
            point_span: child_point_span,
        };

        // NOTE: Ideally this function would not calculate the byte offsets and points separately,
        // as this requires two round-trips to the binary search. However, it's left this way for simplicity.
        let (before, line, after) = self.retrieve_delta_lines(byte_span.start_index as usize, 2, 4);
        let leftmost = before
            .map(|span| span.start_index)
            .unwrap_or(line.start_index) as usize;
        let rightmost = after.map(|span| span.end_index).unwrap_or(line.end_index) as usize;
        let surrounding_bs = ByteSpan::new(leftmost, rightmost);
        let surrounding_ps = self.get_point_span(surrounding_bs);
        let surrounding = Located {
            child: &self.data[surrounding_bs.as_range()],
            byte_span: surrounding_bs,
            point_span: surrounding_ps,
        };

        Context { surrounding, child }
    }

    /// Returns a [`ByteSpan`] of the line that contains `offset`, as well as all lines
    /// contained included by `lines_before` and lines included by `lines_after`, clamped
    /// to the existing lines.
    ///
    /// For example, given:
    /// ```text
    /// 1. abc---def---ghi
    /// 2. ----hello-world--------------
    ///               ^ offset
    /// 3. jkl---mno---pqr
    /// 4. stu---vwx---yz-----
    /// 5. 1---2---3---4---5
    /// ```
    ///
    /// `retrieve_delta_line(27, 2, 0)` will return
    /// ```text
    /// Some("abc---def---ghi\n"),         // Some(ByteSpan)
    /// "----hello-world--------------\n", // ByteSpan
    /// None                               // None
    /// ```
    ///
    /// `retrieve_delta_line(27, 0, 2)` will return
    /// ```text
    /// None,                                          // None
    /// "----hello-world--------------\n",             // ByteSpan
    /// Some("jkl---mno---pqr\nstu---vwx---yz-----\n") // Some(ByteSpan)
    /// ```
    ///
    /// # Panics
    /// Panics if `offset` is out-of-bounds of the underlying data.
    pub fn retrieve_delta_lines(
        &self,
        offset: usize,
        lines_before: usize,
        lines_after: usize,
    ) -> (Option<ByteSpan>, ByteSpan, Option<ByteSpan>) {
        assert!(offset < self.data.len(), "index {offset} out of range");
        let line_to_byte_span = |line: &[u8]| -> ByteSpan {
            let start_index = line.as_ptr() as usize - self.data.as_ptr() as usize;
            ByteSpan::new(start_index, start_index + line.len())
        };

        let (line_number, requested_line_span) = self.find_line_span(offset);

        let preceding_lines = (lines_before > 0)
            .then(|| {
                // We know the `line_number` of this `offset`, so we know the index of it in the vector.
                // The preceding line byte offsets are the values before the `line_number` as an index.
                let line_offsets = self.line_offsets.borrow();
                // There are no preceding lines if this is the first line.
                if line_number == 1 {
                    None
                } else {
                    let line_idx = line_number - 1;
                    let offsets = line_offsets
                        .get(line_idx.saturating_sub(lines_before)..line_idx)
                        .expect("line_offsets should have at least two members before");
                    let first = *offsets.first().expect("vector should not be empty");
                    Some(ByteSpan::new(
                        first,
                        requested_line_span.start_index as usize,
                    ))
                }
            })
            .flatten();

        // NOTE: for simplicity's sake, this does not add to the cache when we scan ahead, though
        // ideally it would.
        let following_lines = (lines_after > 0)
            .then(|| {
                let lines = BStr::new(&self.data[requested_line_span.start_index as usize..])
                    .lines_with_terminator()
                    // Always skip the starting line
                    .skip(1)
                    .map(line_to_byte_span)
                    .take(lines_after)
                    .collect::<Vec<_>>();
                // If it exists, the first item of the vector represents the item nearest to the target
                // line, and the last item is the furthest away.
                lines.first().map(|leftmost_span| {
                    let rightmost_span = lines
                        .last()
                        .expect("if there is a last, there should be a first");
                    ByteSpan::new(
                        leftmost_span.start_index as usize,
                        rightmost_span.end_index as usize,
                    )
                })
            })
            .flatten();

        (preceding_lines, requested_line_span, following_lines)
    }

    /// Performs a binary search over cached line offsets, and iterative search over graphemes
    fn search_for_point(&self, offset: usize) -> Point {
        let (line_number, byte_span) = self.find_line_span(offset);
        let line_start_byte = byte_span.start_index as usize;

        let col_number = BStr::new(&self.data[line_start_byte..offset])
            .graphemes()
            // Handle carriage returns by filtering out b`\r`. The iterator treats b'\r' as a grapheme
            .filter(|&grapheme| grapheme != "\r")
            .count()
            + 1;

        Point::new(line_number as u32, col_number as u32)
    }

    /// Performs a caching scan and returns the line number and [`ByteSpan`] that contains `byte_offset`.
    fn find_line_span(&self, byte_offset: usize) -> (LineNumber, ByteSpan) {
        self.cache_up_to(byte_offset);

        let line_offsets = self.line_offsets.borrow();
        let (line_index, line_start_byte) = match line_offsets.binary_search(&byte_offset) {
            Ok(exact_index) => (exact_index, byte_offset),
            Err(hypothetical_index) => {
                // If `Err`, the function returns the index this `byte_offset` would be inserted at,
                // so we know the previous index's value represents the start of the line this offset
                // is a column on.
                let previous_index = hypothetical_index.saturating_sub(1);
                // If `offset` was 0, always return line 1.
                let previous_line_start_byte =
                    *line_offsets.get(previous_index).unwrap_or(&0_usize);
                (previous_index, previous_line_start_byte)
            }
        };
        // If this does not exist in the vector, it must be an empty line, so it will be equal to `line_start_byte`.
        let next_line_start_byte = *line_offsets.get(line_index + 1).unwrap_or(&line_start_byte);
        let line_number = line_index + 1;
        let byte_span = ByteSpan::new(line_start_byte, next_line_start_byte);

        (line_number, byte_span)
    }

    /// Caches the line information up to the given (inclusive) offset.
    fn cache_up_to(&self, offset: usize) {
        if offset <= self.scanned_up_to.get() {
            return;
        }
        for line in BStr::new(&self.data[self.scanned_up_to.get()..]).lines_with_terminator() {
            let start_index = line.as_ptr() as usize - self.data.as_ptr() as usize;
            let end_index = start_index + line.len();
            let mut line_offsets = self.line_offsets.borrow_mut();
            line_offsets.push(end_index);
            if offset >= start_index && offset < end_index {
                self.scanned_up_to.set(end_index);
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::common::ByteSpan;
    use crate::location::{Point, PointLocator, PointSpan};

    /// A helper to assert on the visual representation of a test's ByteSpan
    fn text_for(text: &str, span: Option<ByteSpan>) -> Option<&str> {
        span.and_then(|span| text.get(span.as_range()))
    }

    /// Gets the line/col of an offset in the middle of a line
    #[test]
    fn point_mid_line() {
        let text = "The quick brown\nfox jumps over\nthe lazy dog";
        let locator = PointLocator::new(text.as_bytes());
        assert_eq!(locator.get_point(6), Point::new(1, 7));
        assert_eq!(locator.get_point(7), Point::new(1, 8));
        assert_eq!(locator.get_point(8), Point::new(1, 9));
        assert_eq!(locator.get_point(24), Point::new(2, 9));
        assert_eq!(locator.get_point(23), Point::new(2, 8));
        assert_eq!(locator.get_point(22), Point::new(2, 7));
        assert_eq!(locator.get_point(39), Point::new(3, 9));
        assert_eq!(locator.get_point(37), Point::new(3, 7));
        assert_eq!(locator.get_point(38), Point::new(3, 8));
    }

    #[test]
    fn point_grapheme() {
        let text = "The quick brown\n🦊 jumps over\nthe lazy 🐕\n";
        let locator = PointLocator::new(text.as_bytes());
        assert_eq!(locator.get_point(16), Point::new(2, 1));
        assert_eq!(locator.get_point(18), Point::new(2, 2));
        assert_eq!(locator.get_point(41), Point::new(3, 10));
        assert_eq!(locator.get_point(43), Point::new(3, 11));
    }

    #[test]
    fn point_line_boundary() {
        let text = "The quick brown\nfox jumps over\nthe lazy dog";
        let locator = PointLocator::new(text.as_bytes());
        assert_eq!(locator.get_point(0), Point::new(1, 1));
        assert_eq!(text.as_bytes()[15], b'\n');
        assert_eq!(locator.get_point(15), Point::new(1, 16));
        assert_eq!(locator.get_point(16), Point::new(2, 1));

        let text = "The quick brown\r\nfox jumps over\nthe lazy dog";
        let locator = PointLocator::new(text.as_bytes());
        assert_eq!(locator.get_point(15), Point::new(1, 16));
        assert_eq!(locator.get_point(17), Point::new(2, 1));
    }

    #[test]
    fn point_empty_line() {
        let text = "The quick brown\n\n";
        let locator = PointLocator::new(text.as_bytes());
        assert_eq!(locator.get_point(15), Point::new(1, 16));
        assert_eq!(locator.get_point(16), Point::new(2, 1));
        assert_eq!(locator.get_point(17), Point::new(3, 1));
    }

    #[test]
    fn point_empty_input() {
        let text = "";
        let locator = PointLocator::new(text.as_bytes());
        assert_eq!(locator.get_point(0), Point::new(1, 1));
    }

    /// The lookup should treat a carriage return as a single column.
    #[test]
    fn point_carriage_return() {
        let text = "The quick brown\n\r\n\nfox jumps over";
        let locator = PointLocator::new(text.as_bytes());
        assert_eq!(locator.get_point(16), Point::new(2, 1));
        assert_eq!(text.as_bytes()[16], b'\r');
        assert_eq!(text.as_bytes()[17], b'\n');
        assert_eq!(locator.get_point(17), Point::new(2, 1));
        assert_eq!(locator.get_point(18), Point::new(3, 1));
    }

    #[test]
    fn point_slice_boundary() {
        let text = "The quick brown\nfox jumps over\nthe lazy dog\n";
        let locator = PointLocator::new(text.as_bytes());
        assert_eq!(locator.get_point(0), Point::new(1, 1));
        assert_eq!(locator.get_point(text.len()), Point::new(4, 1));
    }

    #[test]
    #[should_panic(expected = "range end index 4 out of range")]
    fn out_of_bounds_panics() {
        let text = "abc";
        let locator = PointLocator::new(text.as_bytes());
        let _should_panic = locator.get_point(text.len() + 1);
    }

    #[test]
    fn point_span_boundary() {
        let text = "The quick brown\nfox jumps over\nthe lazy dog\n";
        let locator = PointLocator::new(text.as_bytes());
        assert_eq!(
            locator.get_point_span(ByteSpan::new(0, text.len())),
            PointSpan::new(Point::new(1, 1), Point::new(4, 1))
        );
    }

    #[test]
    fn point_span_mid_line() {
        let text = "The quick brown\nfox jumps over\nthe lazy dog\n";
        let locator = PointLocator::new(text.as_bytes());
        assert_eq!(
            locator.get_point_span(ByteSpan::new(20, 25)),
            PointSpan::new(Point::new(2, 5), Point::new(2, 10))
        );
    }

    #[test]
    fn delta_lines_saturating_sub() {
        let text = "abc\ndef\nghi\njkl\nmno\npqr";
        let locator = PointLocator::new(text.as_bytes());
        let (before, line, after) = locator.retrieve_delta_lines(5, 2, 2);
        assert_eq!(text_for(text, before), Some("abc\n"));
        assert_eq!(text_for(text, Some(line)), Some("def\n"));
        assert_eq!(text_for(text, after), Some("ghi\njkl\n"));
    }

    /// Tests that the line offset is properly calculated when the value is exactly at the start of a line
    #[test]
    fn delta_lines_line_boundary() {
        let text = "abc\ndef\nghi\njkl\nmno\npqr";
        let locator = PointLocator::new(text.as_bytes());
        let (before, line, after) = locator.retrieve_delta_lines(4, 1, 1);
        assert_eq!(text_for(text, before), Some("abc\n"));
        assert_eq!(text_for(text, Some(line)), Some("def\n"));
        assert_eq!(text_for(text, after), Some("ghi\n"));
    }

    #[test]
    fn delta_lines_empty_lines() {
        let text = "abc\ndef\n\njkl\nmno\npqr";
        let locator = PointLocator::new(text.as_bytes());
        let (before, line, after) = locator.retrieve_delta_lines(5, 0, 3);
        assert_eq!(text_for(text, before), None);
        assert_eq!(text_for(text, Some(line)), Some("def\n"));
        assert_eq!(text_for(text, after), Some("\njkl\nmno\n"));
    }

    #[test]
    fn delta_lines_no_delta() {
        let text = "abc\ndef\nghi\njkl\nmno\npqr";
        let locator = PointLocator::new(text.as_bytes());
        let (before, line, after) = locator.retrieve_delta_lines(5, 0, 0);
        assert_eq!(text_for(text, before), None);
        assert_eq!(text_for(text, Some(line)), Some("def\n"));
        assert_eq!(text_for(text, after), None);
    }

    #[test]
    fn delta_lines_first_line() {
        let text = "abc\ndef\nghi\njkl\nmno\npqr";
        let locator = PointLocator::new(text.as_bytes());
        let (before, line, after) = locator.retrieve_delta_lines(2, 1, 1);
        assert_eq!(text_for(text, before), None);
        assert_eq!(text_for(text, Some(line)), Some("abc\n"));
        assert_eq!(text_for(text, after), Some("def\n"));
    }

    #[test]
    fn delta_lines_last_line() {
        let text = "abc\ndef\nghi\njkl\nmno\npqr";
        let locator = PointLocator::new(text.as_bytes());
        let (before, line, after) = locator.retrieve_delta_lines(21, 1, 1);
        assert_eq!(text_for(text, before), Some("mno\n"));
        assert_eq!(text_for(text, Some(line)), Some("pqr"));
        assert_eq!(text_for(text, after), None);
    }

    /// Ensure that the function panics and doesn't return Some("<last_line>") for `before`, (although
    /// that technically is the line before an out-of-bounds offset).
    #[test]
    #[should_panic(expected = "index 50 out of range")]
    fn delta_lines_panics_out_of_bounds() {
        let text = "abc\ndef\nghi\njkl\nmno\npqr";
        let locator = PointLocator::new(text.as_bytes());
        let (before, line, after) = locator.retrieve_delta_lines(50, 1, 1);
        assert_eq!(text_for(text, before), Some("mno\n"));
        assert_eq!(text_for(text, Some(line)), Some("pqr"));
        assert_eq!(text_for(text, after), None);
    }
}
