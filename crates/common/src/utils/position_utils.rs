use crate::model::position::Position;
use bstr::BStr;
use bstr::ByteSlice;
use line_index::{LineCol, LineIndex, WideEncoding};

/// Precomputed per-line index for fast repeated UTF-8 byte-column → UTF-16 code-unit column
/// conversion.
///
/// Build once per source string with [`LineColumnIndex::new`], then call
/// [`byte_col_to_utf16_col`](LineColumnIndex::byte_col_to_utf16_col) for every tree-sitter node
/// on that source. Backed by [`line_index::LineIndex`] from the rust-analyzer project.
///
/// ## Line model
///
/// [`line_index::LineIndex`] splits on `\n` only, which mirrors tree-sitter's line model exactly.
/// Tree-sitter does not treat a bare `\r` (classic Mac OS 9) as a line terminator; for Windows
/// `\r\n` files the `\r` is counted as part of the column on the same line, matching
/// tree-sitter's `Point.column` values. Using a broader splitter (e.g. Unicode line endings)
/// would diverge from tree-sitter and produce wrong UTF-16 columns.
#[derive(Debug)]
pub struct LineColumnIndex(LineIndex);

impl LineColumnIndex {
    /// Builds the index by scanning `source`.
    pub fn new(source: &str) -> Self {
        Self(LineIndex::new(source))
    }

    /// Converts a tree-sitter 0-based `(row, byte_col)` point to a 1-based UTF-16 code-unit
    /// column.
    ///
    /// Returns `None` if `(row, byte_col)` falls outside the indexed source.
    pub fn byte_col_to_utf16_col(&self, row: usize, byte_col: usize) -> Option<u32> {
        let lc = LineCol {
            line: row as u32,
            col: byte_col as u32,
        };
        self.0.to_wide(WideEncoding::Utf16, lc).map(|w| w.col + 1)
    }
}

/// Get position of an offset in a code and return a [Position].
pub fn get_position_in_string(content: &str, offset: usize) -> anyhow::Result<Position> {
    if offset >= content.len() {
        anyhow::bail!("offset is larger than content length");
    }

    let bstr = BStr::new(&content);

    let mut line_number: u32 = 1;
    let lines = bstr.lines_with_terminator();
    for line in lines {
        let start_index = line.as_ptr() as usize - content.as_ptr() as usize;
        let end_index = start_index + line.len();

        if (start_index..end_index).contains(&offset) {
            let mut col_number: u32 = 1;
            for (grapheme_start, grapheme_end, _) in line.grapheme_indices() {
                let grapheme_absolute_start = start_index + grapheme_start;
                let grapheme_absolute_end = start_index + grapheme_end;

                // It's exactly the index we are looking for.
                if offset == grapheme_absolute_start {
                    return Ok(Position {
                        line: line_number,
                        col: col_number,
                    });
                }

                // The offset is within the grapheme we are looking for, it's the next col.
                if (grapheme_absolute_start..grapheme_absolute_end).contains(&offset) {
                    return Ok(Position {
                        line: line_number,
                        col: col_number + 1,
                    });
                }
                col_number += 1;
            }
        }
        line_number += 1;
    }

    Err(anyhow::anyhow!("cannot find position"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_position_in_string() {
        assert_eq!(
            get_position_in_string("foobarbaz", 3).unwrap(),
            Position::new(1, 4)
        );
    }

    #[test]
    fn test_get_position_in_string_out_of_bounds() {
        assert!(get_position_in_string("foobarbaz", 42).is_err());
    }

    #[test]
    fn test_grapheme() {
        let text = "The quick brown\n🦊 jumps over\nthe lazy 🐕\n";
        assert_eq!(
            get_position_in_string(text, 16).unwrap(),
            Position::new(2, 1)
        );
        assert_eq!(
            get_position_in_string(text, 18).unwrap(),
            Position::new(2, 2)
        );
        assert_eq!(
            get_position_in_string(text, 41).unwrap(),
            Position::new(3, 10)
        );
        assert_eq!(
            get_position_in_string(text, 43).unwrap(),
            Position::new(3, 11)
        );
    }

    #[test]
    fn test_point_midline() {
        let text = "The quick brown\nfox jumps over\nthe lazy dog";
        assert_eq!(
            get_position_in_string(text, 6).unwrap(),
            Position::new(1, 7)
        );
        assert_eq!(
            get_position_in_string(text, 7).unwrap(),
            Position::new(1, 8)
        );
        assert_eq!(
            get_position_in_string(text, 8).unwrap(),
            Position::new(1, 9)
        );
        assert_eq!(
            get_position_in_string(text, 24).unwrap(),
            Position::new(2, 9)
        );
        assert_eq!(
            get_position_in_string(text, 23).unwrap(),
            Position::new(2, 8)
        );
        assert_eq!(
            get_position_in_string(text, 22).unwrap(),
            Position::new(2, 7)
        );
        assert_eq!(
            get_position_in_string(text, 39).unwrap(),
            Position::new(3, 9)
        );
        assert_eq!(
            get_position_in_string(text, 37).unwrap(),
            Position::new(3, 7)
        );
        assert_eq!(
            get_position_in_string(text, 38).unwrap(),
            Position::new(3, 8)
        );
    }

    #[test]
    fn point_slice_boundary() {
        let text = "The quick brown\nfox jumps over\nthe lazy dog\n";
        assert_eq!(
            get_position_in_string(text, 0).unwrap(),
            Position::new(1, 1)
        );
        assert_eq!(
            get_position_in_string(text, text.len() - 1).unwrap(),
            Position::new(3, 13)
        );
    }

    #[test]
    fn byte_col_to_utf16_col_calls_to_wide_utf16() {
        // Single source string with one non-ASCII char. We only need to prove our wrapper
        // delegates to line_index::LineIndex::to_wide(WideEncoding::Utf16, ..) and adds 1.
        // Exhaustive encoding cases live in the line-index crate's own test suite.
        let idx = LineColumnIndex::new("a\u{65E5}b"); // a 日 b
                                                      // byte 0 ('a') → 0 UTF-16 units before, +1 = 1
        assert_eq!(idx.byte_col_to_utf16_col(0, 0).unwrap(), 1);
        // byte 4 ('b' after 日 which is 3 UTF-8 bytes / 1 UTF-16 unit) → 2 UTF-16 units before, +1 = 3
        assert_eq!(idx.byte_col_to_utf16_col(0, 4).unwrap(), 3);
    }
}
