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
