use common::model::position::Position;
use kernel::model::rule::{RuleCategory, RuleSeverity};

use derive_builder::Builder;
use kernel::model::violation::{Edit, EditType, Fix, Violation};
use serde::{Deserialize, Serialize};

/// because of our naming conventions that mix camelCase in the JS code
/// and other parts of rosie adn the snake_case that got adopted for our
/// API, we need to have a model for the server that exposes only
/// snake_case data.
///
/// Therefore, for each data type from the model in the kernel, we duplicate
/// the classes and make sure the casing follows what is expected.
#[derive(Deserialize, Debug, Serialize, Clone, Builder)]
pub struct ServerEdit {
    pub start: Position,
    pub end: Option<Position>,
    pub edit_type: EditType,
    pub content: Option<String>,
}

#[derive(Deserialize, Debug, Serialize, Clone, Builder)]
pub struct ServerFix {
    pub description: String,
    pub edits: Vec<ServerEdit>,
}

#[derive(Deserialize, Debug, Serialize, Clone, Builder)]
pub struct ServerViolation {
    pub start: Position,
    pub end: Position,
    pub message: String,
    pub severity: RuleSeverity,
    pub category: RuleCategory,
    pub fixes: Vec<ServerFix>,
}

/// Transform an edit from the kernel into an edit that is surfaced by the server.
pub fn edit_to_server(edit: &Edit) -> ServerEdit {
    ServerEdit {
        start: edit.start.clone(),
        end: edit.end.clone(),
        edit_type: edit.edit_type,
        content: edit.content.clone(),
    }
}

/// Transform a fix from the kernel data model into a fix that is surfaced by the server.
pub fn fix_to_server(fix: &Fix) -> ServerFix {
    ServerFix {
        description: fix.description.clone(),
        edits: fix.edits.iter().map(edit_to_server).collect(),
    }
}

/// Transform a violation from the kernel data model into what is surfaced by the server.
pub fn violation_to_server(violation: &Violation) -> ServerViolation {
    ServerViolation {
        start: violation.start.clone(),
        end: violation.end.clone(),
        message: violation.message.clone(),
        severity: violation.severity,
        category: violation.category,
        fixes: violation.fixes.iter().map(fix_to_server).collect(),
    }
}
