use kernel::model::analysis::TreeSitterNode;
use kernel::model::common::Position;
use serde_derive::{Deserialize, Serialize};

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

pub fn convert_tree_sitter_node_for_server(node: TreeSitterNode) -> ServerTreeSitterNode {
    let children: Vec<ServerTreeSitterNode> = node
        .children
        .into_iter()
        .map(convert_tree_sitter_node_for_server)
        .collect();

    ServerTreeSitterNode {
        ast_type: node.ast_type,
        start: node.start.clone(),
        end: node.end.clone(),
        field_name: node.field_name,
        children,
    }
}
