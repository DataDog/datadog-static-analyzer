use crate::model::common::Position;
use crate::model::rule::{RuleCategory, RuleSeverity};

use derive_builder::Builder;
use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Deserialize, Debug, Serialize, Eq, PartialEq)]
pub enum EditType {
    #[serde(rename = "ADD")]
    Add,
    #[serde(rename = "REMOVE")]
    Remove,
    #[serde(rename = "UPDATE")]
    Update,
}

#[derive(Deserialize, Debug, Serialize, Clone, Builder)]
pub struct Edit {
    pub start: Position,
    pub end: Option<Position>,
    #[serde(rename = "editType")]
    pub edit_type: EditType,
    pub content: Option<String>,
}

#[derive(Deserialize, Debug, Serialize, Clone, Builder)]
pub struct Fix {
    pub description: String,
    pub edits: Vec<Edit>,
}

#[derive(Deserialize, Debug, Serialize, Clone, Builder)]
pub struct Violation {
    pub start: Position,
    pub end: Position,
    pub message: String,
    pub severity: RuleSeverity,
    pub category: RuleCategory,
    pub fixes: Vec<Fix>,
}
