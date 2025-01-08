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
    #[serde(rename = "ELIXIR")]
    Elixir,
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
    PHP,
    #[serde(rename = "MARKDOWN")]
    Markdown,
    #[serde(rename = "APEX")]
    Apex,
    R,
    SQL,
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
    Language::PHP,
    Language::Markdown,
    Language::Apex,
    Language::R,
    Language::SQL,
];

impl fmt::Display for Language {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Csharp => "c#",
            Self::Dockerfile => "dockerfile",
            Self::Go => "go",
            Self::Elixir => "elixir",
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
            Self::PHP => "php",
            Self::Markdown => "markdown",
            Self::Apex => "apex",
            Self::R => "r",
            Self::SQL => "sql",
        };
        write!(f, "{s}")
    }
}
