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
    /// Falls back to `byte_col + 1` (correct for ASCII-only content) when the coordinates fall
    /// outside the indexed source, preserving pre-existing behaviour for out-of-range inputs.
    pub fn byte_col_to_utf16_col(&self, row: usize, byte_col: usize) -> u32 {
        let lc = LineCol {
            line: row as u32,
            col: byte_col as u32,
        };
        self.0
            .to_wide(WideEncoding::Utf16, lc)
            .map(|w| w.col + 1)
            .unwrap_or((byte_col as u32) + 1)
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

    // ── LineColumnIndex tests ─────────────────────────────────────────────────

    #[test]
    fn lci_ascii_fast_path() {
        // Pure ASCII: UTF-16 col == byte col + 1 for every position.
        let idx = LineColumnIndex::new("hello world\nfoo bar");
        assert_eq!(idx.byte_col_to_utf16_col(0, 0), 1); // 'h' → col 1
        assert_eq!(idx.byte_col_to_utf16_col(0, 5), 6); // ' ' → col 6
        assert_eq!(idx.byte_col_to_utf16_col(1, 3), 4); // ' ' on line 2 → col 4
    }

    #[test]
    fn lci_bmp_non_ascii() {
        // 'é' is U+00E9: 2 UTF-8 bytes, 1 UTF-16 code unit.
        // Source: "café\nend"  — bytes: c(0) a(1) f(2) é(3,4) \n(5)
        let src = "caf\u{00E9}\nend";
        let idx = LineColumnIndex::new(src);
        // byte_col 3 (start of é) → prefix "caf" = 3 UTF-16 units → col 4
        assert_eq!(idx.byte_col_to_utf16_col(0, 3), 4);
        // byte_col 5 (past é, 3 + 2 bytes) → prefix "café" = 4 UTF-16 units → col 5
        assert_eq!(idx.byte_col_to_utf16_col(0, 5), 5);
        // line 1 is ASCII
        assert_eq!(idx.byte_col_to_utf16_col(1, 3), 4);
    }

    #[test]
    fn lci_supplementary_plane_emoji() {
        // '🚀' is U+1F680: 4 UTF-8 bytes, 2 UTF-16 code units (surrogate pair).
        // Source: "x🚀y"
        // byte positions: x(0) 🚀(1,2,3,4) y(5)
        let src = "x\u{1F680}y";
        let idx = LineColumnIndex::new(src);
        // byte_col 0 → col 1 (before 'x')
        assert_eq!(idx.byte_col_to_utf16_col(0, 0), 1);
        // byte_col 1 → prefix = "x" → 1 UTF-16 unit → col 2
        assert_eq!(idx.byte_col_to_utf16_col(0, 1), 2);
        // byte_col 5 → prefix = "x🚀" → x(1) + 🚀(2) = 3 UTF-16 units → col 4
        assert_eq!(idx.byte_col_to_utf16_col(0, 5), 4);
        // byte_col 6 → prefix = "x🚀y" → 3+1 = 4 UTF-16 units → col 5
        assert_eq!(idx.byte_col_to_utf16_col(0, 6), 5);
    }

    #[test]
    fn lci_cjk() {
        // '日' is U+65E5: 3 UTF-8 bytes, 1 UTF-16 code unit.
        // Source: "日本"
        // bytes: 日(0,1,2) 本(3,4,5)
        let src = "\u{65E5}\u{672C}"; // 日本
        let idx = LineColumnIndex::new(src);
        // byte_col 0 → col 1
        assert_eq!(idx.byte_col_to_utf16_col(0, 0), 1);
        // byte_col 3 → prefix = "日" → 1 UTF-16 unit → col 2
        assert_eq!(idx.byte_col_to_utf16_col(0, 3), 2);
        // byte_col 6 → prefix = "日本" → 2 UTF-16 units → col 3
        assert_eq!(idx.byte_col_to_utf16_col(0, 6), 3);
    }

    #[test]
    fn lci_combining_mark() {
        // 'e' + U+0301 (combining acute accent): 2 codepoints, 2 UTF-16 code units, 1 grapheme.
        // Source: "e\u{0301}x"
        // bytes: e(0) \u{0301}(1,2) x(3)
        let src = "e\u{0301}x";
        let idx = LineColumnIndex::new(src);
        // byte_col 0 → col 1
        assert_eq!(idx.byte_col_to_utf16_col(0, 0), 1);
        // byte_col 1 → prefix = "e" → 1 UTF-16 unit → col 2
        assert_eq!(idx.byte_col_to_utf16_col(0, 1), 2);
        // byte_col 3 → prefix = "e\u{0301}" → 2 UTF-16 units → col 3
        assert_eq!(idx.byte_col_to_utf16_col(0, 3), 3);
        // byte_col 4 → prefix = "e\u{0301}x" → 3 UTF-16 units → col 4
        assert_eq!(idx.byte_col_to_utf16_col(0, 4), 4);
    }

    #[test]
    fn lci_crlf_line_endings() {
        // CRLF: tree-sitter counts \n as the line terminator and the col includes \r.
        // Source: "ab\r\ncd"
        // Line 0 bytes: a(0) b(1) \r(2) \n(3) → line_start[1] = 4
        // Line 1 bytes: c(0 rel) d(1 rel)
        let src = "ab\r\ncd";
        let idx = LineColumnIndex::new(src);
        // Line 0
        assert_eq!(idx.byte_col_to_utf16_col(0, 0), 1);
        assert_eq!(idx.byte_col_to_utf16_col(0, 2), 3); // past "ab" → 2+1=3
                                                        // Line 1
        assert_eq!(idx.byte_col_to_utf16_col(1, 0), 1);
        assert_eq!(idx.byte_col_to_utf16_col(1, 2), 3);
    }

    #[test]
    fn lci_eol_boundary() {
        // byte_col == 0 on the start of any line → col 1.
        let src = "abc\ndef\nghi";
        let idx = LineColumnIndex::new(src);
        assert_eq!(idx.byte_col_to_utf16_col(0, 0), 1);
        assert_eq!(idx.byte_col_to_utf16_col(1, 0), 1);
        assert_eq!(idx.byte_col_to_utf16_col(2, 0), 1);
        // byte_col at end of "abc" (3 bytes) → col 4
        assert_eq!(idx.byte_col_to_utf16_col(0, 3), 4);
    }

    #[test]
    fn lci_empty_line() {
        // An empty line: byte_col 0 → col 1.
        let src = "\n\nfoo";
        let idx = LineColumnIndex::new(src);
        assert_eq!(idx.byte_col_to_utf16_col(0, 0), 1);
        assert_eq!(idx.byte_col_to_utf16_col(1, 0), 1);
        assert_eq!(idx.byte_col_to_utf16_col(2, 0), 1);
    }
}
