use kernel::model::analysis::TreeSitterNode;
use serde_derive::{Deserialize, Serialize};

#[derive(Clone, Deserialize, Debug, Serialize)]
pub struct TreeSitterResponse {
    pub result: Option<TreeSitterNode>,
    pub errors: Vec<String>,
}
