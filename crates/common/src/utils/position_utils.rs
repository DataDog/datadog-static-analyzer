use crate::model::position::Position;
use bstr::BStr;
use bstr::ByteSlice;

/// Get position of an offset in a code and return a [[Position]].
pub fn get_position_in_string(content: &str, offset: usize) -> anyhow::Result<Position> {
    let bstr = BStr::new(&content);

    let mut line_number: u32 = 1;

    for line in bstr.lines_with_terminator() {
        let start_index = line.as_ptr() as usize - content.as_ptr() as usize;
        let end_index = start_index + line.len();

        if offset >= start_index && offset < end_index {
            let mut col_number: u32 = 1;
            for grapheme in line.grapheme_indices() {
                // It's exactly the index we are looking for.
                if offset == start_index + grapheme.0 {
                    return Ok(Position {
                        line: line_number,
                        col: col_number,
                    });
                }

                // The offset is within the grapheme we are looking for, it's the next col.
                if offset >= start_index + grapheme.0 && offset < start_index + grapheme.1 {
                    return Ok(Position {
                        line: line_number,
                        col: col_number + 1,
                    });
                }
                col_number = col_number + 1;
            }
        }
        line_number = line_number + 1;
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
}
