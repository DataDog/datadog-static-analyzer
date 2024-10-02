// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use std::fmt;

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
