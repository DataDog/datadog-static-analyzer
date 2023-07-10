use crate::model::tree_sitter_tree_node::ServerTreeSitterNode;
use serde::{Deserialize, Serialize};

#[derive(Clone, Deserialize, Debug, Serialize)]
pub struct TreeSitterResponse {
    pub result: Option<ServerTreeSitterNode>,
    pub errors: Vec<String>,
}
