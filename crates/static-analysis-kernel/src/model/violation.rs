use crate::model::rule::{RuleCategory, RuleSeverity};
use common::model::position::{Position, Region};

use derive_builder::Builder;
use serde::{Deserialize, Serialize};

/// The function or method that encloses a violation.
#[derive(Deserialize, Debug, Serialize, Clone, PartialEq)]
pub struct EnclosingFunction {
    /// Simple identifier (e.g. `handle`, `doSomething`).
    pub name: String,
    /// Service-definition qualified name: `ClassName.methodName` when the function belongs to a
    /// class or struct, or just `methodName` for top-level functions.
    pub fully_qualified_name: String,
}

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
    /// Whether this violation was suppressed by an inline comment (e.g. `no-dd-sa`).
    #[serde(default)]
    #[builder(default)]
    pub is_suppressed: bool,
    /// The function or method enclosing this violation, if any.
    #[serde(default)]
    #[builder(default)]
    pub enclosing_function: Option<EnclosingFunction>,
}
