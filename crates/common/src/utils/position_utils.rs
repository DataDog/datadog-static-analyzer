use crate::model::position::Position;
use bstr::BStr;
use bstr::ByteSlice;

/// Get position of an offset in a code and return a [Position].
pub fn get_position_in_string(content: &str, offset: usize) -> anyhow::Result<Position> {
    let bstr = BStr::new(&content);

    let mut line_number: u32 = 1;
    let lines = bstr.lines_with_terminator();
    let mut last_end_index: usize = 0;
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
        last_end_index = end_index;
    }

    // We are on the last character
    if last_end_index > 0 && last_end_index == offset {
        return Ok(Position {
            line: line_number,
            col: 1,
        });
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
            get_position_in_string(text, text.len()).unwrap(),
            Position::new(4, 1)
        );
    }
}
