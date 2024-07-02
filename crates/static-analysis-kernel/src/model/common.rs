use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Clone, Deserialize, Debug, Serialize, Eq, PartialEq)]
pub enum OutputFormat {
    Csv,
    Json,
    Sarif,
}

impl fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Csv => "CSV",
            Self::Json => "JSON",
            Self::Sarif => "SARIF",
        };
        write!(f, "{s}")
    }
}

#[derive(Copy, Clone, Deserialize, Debug, Serialize, Eq, Hash, PartialEq)]
pub enum Language {
    #[serde(rename = "CSHARP")]
    Csharp,
    #[serde(rename = "DOCKERFILE")]
    Dockerfile,
    #[serde(rename = "GO")]
    Go,
    #[serde(rename = "JAVA")]
    Java,
    #[serde(rename = "JAVASCRIPT")]
    JavaScript,
    #[serde(rename = "JSON")]
    Json,
    #[serde(rename = "KOTLIN")]
    Kotlin,
    #[serde(rename = "PYTHON")]
    Python,
    #[serde(rename = "RUBY")]
    Ruby,
    #[serde(rename = "RUST")]
    Rust,
    #[serde(rename = "SWIFT")]
    Swift,
    #[serde(rename = "TERRAFORM")]
    Terraform,
    #[serde(rename = "TYPESCRIPT")]
    TypeScript,
    #[serde(rename = "YAML")]
    Yaml,
    #[serde(rename = "STARLARK")]
    Starlark,
    #[serde(rename = "BASH")]
    Bash,
}

#[allow(dead_code)]
pub static ALL_LANGUAGES: &[Language] = &[
    Language::Csharp,
    Language::Dockerfile,
    Language::Go,
    Language::Java,
    Language::JavaScript,
    Language::Json,
    Language::Kotlin,
    Language::Python,
    Language::Ruby,
    Language::Rust,
    Language::Swift,
    Language::TypeScript,
    Language::Terraform,
    Language::Yaml,
    Language::Starlark,
    Language::Bash,
];

impl fmt::Display for Language {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Csharp => "c#",
            Self::Dockerfile => "dockerfile",
            Self::Go => "go",
            Self::Java => "java",
            Self::JavaScript => "javascript",
            Self::Json => "json",
            Self::Kotlin => "kotlin",
            Self::Python => "python",
            Self::Ruby => "ruby",
            Self::Rust => "rust",
            Self::Swift => "swift",
            Self::Terraform => "terraform",
            Self::TypeScript => "typescript",
            Self::Yaml => "yaml",
            Self::Starlark => "starlark",
            Self::Bash => "bash",
        };
        write!(f, "{s}")
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
