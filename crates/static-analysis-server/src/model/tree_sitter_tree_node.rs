use common::model::position::Position;
use kernel::model::analysis::TreeSitterNode;
use serde::{Deserialize, Serialize};

// This representation is for the server only for an node representation. In the kernel,
// we serialize/deserialize in camelCase since the value is retrieved in JavaScript code.
// The API only emits camel_case_code, which is why we have this class.
#[derive(Clone, Deserialize, Debug, Serialize)]
pub struct ServerTreeSitterNode {
    pub ast_type: String,
    pub start: Position,
    pub end: Position,
    pub field_name: Option<String>,
    pub children: Vec<ServerTreeSitterNode>,
}

impl From<TreeSitterNode> for ServerTreeSitterNode {
    fn from(value: TreeSitterNode) -> Self {
        ServerTreeSitterNode {
            ast_type: value.ast_type,
            start: value.start,
            end: value.end,
            field_name: value.field_name,
            children: value
                .children
                .into_iter()
                .map(ServerTreeSitterNode::from)
                .collect(),
        }
    }
}
