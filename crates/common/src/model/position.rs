// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use std::fmt;

/// A source-code position.
///
/// * `line` — 1-based line number.
/// * `col` — 1-based column number.  The unit depends on the producer:
///   - **Static-analysis kernel** (tree-sitter path): UTF-16 code-unit column.  Matches LSP,
///     VS Code, and the SARIF v2.1 default encoding.  On ASCII-only lines, one UTF-16 code unit
///     equals one byte, so the value is identical to a byte-column.  For non-ASCII characters
///     (CJK ideographs, emoji surrogate pairs, combining marks, etc.) the count reflects UTF-16
///     surrogate-pair expansion.
///   - **Secrets scanner** (`get_position_in_string`): Unicode-grapheme-cluster column.  A single
///     user-perceived character (including emoji and composed sequences) counts as one unit
///     regardless of its UTF-8 or UTF-16 size.
#[derive(Deserialize, Debug, Serialize, Clone, Copy, Builder, PartialEq, Eq, Hash)]
pub struct Position {
    pub line: u32,
    pub col: u32,
}

impl Position {
    pub fn new(line: u32, col: u32) -> Self {
        Self { line, col }
    }
}

impl fmt::Display for Position {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "position (line: {}, col: {})", self.line, self.col)
    }
}

/// A contiguous portion of a file.
#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct Region {
    /// The start of a region.
    /// * `line`: A positive integer equal to the line number containing the first character of this region.
    /// * `col`: A positive integer equal to the column number of the first character of this region.
    pub start: Position,
    /// The end of a region.
    /// * `line`: A positive integer equal to the line number containing the last character of this region.
    /// * `col`: A positive integer whose value is one greater than column number of the last character in this region.
    pub end: Position,
}
