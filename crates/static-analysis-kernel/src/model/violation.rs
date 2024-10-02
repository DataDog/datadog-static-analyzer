use crate::model::rule::{RuleCategory, RuleSeverity};
use common::model::position::{Position, Region};

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
    /// An ordered list of regions representing a flow from start to finish.
    pub taint_flow: Option<Vec<Region>>,
}
