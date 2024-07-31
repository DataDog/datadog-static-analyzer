#[derive(Debug, Clone, Default)]
pub struct Line {
    pub row: usize,
    pub content: String,
}

impl Line {
    pub const fn new(row: usize, content: String) -> Self {
        Self { row, content }
    }
}

#[derive(Debug, Clone)]
pub enum Comment {
    Inline {
        line: Line,
        original_content: String,
    },
    Block {
        line: Line,
        above_line: Option<Line>,
        below_line: Option<Line>,
    },
}
