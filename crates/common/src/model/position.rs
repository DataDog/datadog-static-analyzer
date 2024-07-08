// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Deserialize, Debug, Serialize, Clone, Copy, Builder)]
pub struct Position {
    pub line: u32,
    pub col: u32,
}

impl Position {
    pub fn is_invalid(&self) -> bool {
        self.col == 0 || self.line == 0
    }
}

impl PartialEq for Position {
    fn eq(&self, other: &Self) -> bool {
        other.col == self.col && other.line == self.line
    }
}

pub const INVALID_POSITION: Position = Position { line: 0, col: 0 };

impl fmt::Display for Position {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "position (line: {}, col: {})", self.line, self.col)
    }
}
