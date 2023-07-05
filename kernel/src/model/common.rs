use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Deserialize, Debug, Serialize, PartialEq)]
pub enum OutputFormat {
    Json,
    Sarif,
}

impl fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            OutputFormat::Json => "JSON",
            OutputFormat::Sarif => "SARIF",
        };
        write!(f, "{}", s)
    }
}

#[derive(Copy, Clone, Deserialize, Debug, Serialize, Eq, Hash, PartialEq)]
pub enum Language {
    #[serde(rename = "PYTHON")]
    Python,
    #[serde(rename = "JAVASCRIPT")]
    JavaScript,
    #[serde(rename = "TYPESCRIPT")]
    TypeScript,
    #[serde(rename = "RUST")]
    Rust,
}

#[allow(dead_code)]
static ALL_LANGUAGES: &[Language] = &[
    Language::JavaScript,
    Language::Python,
    Language::Rust,
    Language::TypeScript,
];

impl fmt::Display for Language {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Language::JavaScript => "javascript",
            Language::Python => "python",
            Language::Rust => "rust",
            Language::TypeScript => "typescript",
        };
        write!(f, "{}", s)
    }
}

#[derive(Deserialize, Debug, Serialize, Clone, Builder)]
pub struct Position {
    pub line: u32,
    pub col: u32,
}

impl fmt::Display for Position {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "position (line: {}, col: {})", self.line, self.col)
    }
}
