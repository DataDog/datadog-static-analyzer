#[derive(Clone, Debug, PartialEq)]
struct InternalResult {
    rule_index: usize,
    start: Position,
    end: Position,
    start_index: usize,
    end_index: usize,
    validation_status: SecretValidationStatus,
    filtered_by_ast: bool,
}

pub mod ast_filter;
pub mod config;
pub mod file_mgmt;
pub mod model;
pub mod scanner;
pub mod secret_files;

// Re-export Scanner so downstream crates can reference the type without depending on dd_sds directly.
use crate::model::secret_result::SecretValidationStatus;
use common::model::position::Position;
pub use dd_sds::Scanner;
