use crate::constants::{ERROR_CODE_NOT_BASE64, ERROR_CODE_NO_ROOT_NODE};
use crate::model::tree_sitter_tree_node::ServerTreeSitterNode;
use crate::model::tree_sitter_tree_request::TreeSitterRequest;
use crate::model::tree_sitter_tree_response::TreeSitterResponse;
use common::utils::position_utils::LineColumnIndex;
use kernel::analysis::tree_sitter::{get_tree, map_node};
use kernel::utils::decode_base64_string;

// Return the tree for the language and code sent as parameter.
#[tracing::instrument(skip_all)]
pub fn process_tree_sitter_tree_request(request: TreeSitterRequest) -> TreeSitterResponse {
    tracing::debug!("Processing tree-sitter AST generation request");

    let no_root_node = TreeSitterResponse {
        result: None,
        errors: vec![ERROR_CODE_NO_ROOT_NODE.to_string()],
    };

    let Ok(decoded) = decode_base64_string(request.code_base64) else {
        tracing::info!("Validation error: code is not a base64 string");
        return TreeSitterResponse {
            result: None,
            errors: vec![ERROR_CODE_NOT_BASE64.to_string()],
        };
    };

    tracing::debug!(
        "Getting tree-sitter tree (code length: {} bytes)",
        &decoded.len()
    );

    // Note: [get_tree] returns None if the call to tree_sitter::Parser::set_language returns an Err
    let result = get_tree(&decoded, &request.language);
    if result.is_none() {
        tracing::warn!(
            "Unable to create tree-sitter parser for language `{}`",
            request.language
        );
        return no_root_node;
    }

    if let Some(result) = result.map(|tree| {
        let idx = LineColumnIndex::new(&decoded);
        map_node(tree.root_node(), &idx).map(ServerTreeSitterNode::from)
    }) {
        tracing::info!("Successfully completed tree-sitter AST generation");
        TreeSitterResponse {
            result,
            errors: vec![],
        }
    } else {
        tracing::info!("Generated AST contained no root node");
        no_root_node
    }
}

#[cfg(test)]
mod tests {
    use kernel::model::common::Language;

    use super::*;

    #[test]
    fn test_process_tree_sitter_tree_request_happy_path() {
        let request = TreeSitterRequest {
            code_base64: "ZnVuY3Rpb24gdmlzaXQobm9kZSwgZmlsZW5hbWUsIGNvZGUpIHsKICAgIGNvbnN0IGZ1bmN0aW9uTmFtZSA9IG5vZGUuY2FwdHVyZXNbIm5hbWUiXTsKICAgIGlmKGZ1bmN0aW9uTmFtZSkgewogICAgICAgIGNvbnN0IGVycm9yID0gYnVpbGRFcnJvcihmdW5jdGlvbk5hbWUuc3RhcnQubGluZSwgZnVuY3Rpb25OYW1lLnN0YXJ0LmNvbCwgZnVuY3Rpb25OYW1lLmVuZC5saW5lLCBmdW5jdGlvbk5hbWUuZW5kLmNvbCwKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgImludmFsaWQgbmFtZSIsICJDUklUSUNBTCIsICJzZWN1cml0eSIpOwoKICAgICAgICBjb25zdCBlZGl0ID0gYnVpbGRFZGl0KGZ1bmN0aW9uTmFtZS5zdGFydC5saW5lLCBmdW5jdGlvbk5hbWUuc3RhcnQuY29sLCBmdW5jdGlvbk5hbWUuZW5kLmxpbmUsIGZ1bmN0aW9uTmFtZS5lbmQuY29sLCAidXBkYXRlIiwgImJhciIpOwogICAgICAgIGNvbnN0IGZpeCA9IGJ1aWxkRml4KCJ1c2UgYmFyIiwgW2VkaXRdKTsKICAgICAgICBhZGRFcnJvcihlcnJvci5hZGRGaXgoZml4KSk7CiAgICB9Cn0=".to_string(),
            file_encoding: "utf-8".to_string(),
            language: Language::Python,
        };
        let response = process_tree_sitter_tree_request(request);
        assert!(response.errors.is_empty());
        assert!(response.result.is_some());
        assert_eq!("module", response.result.unwrap().ast_type);
    }

    /// `process_tree_sitter_tree_request` emits 1-based UTF-16 columns for non-ASCII content.
    ///
    /// Source: `x = "🚀"; num = 5`
    /// The emoji (🚀, U+1F680) is 4 UTF-8 bytes / 2 UTF-16 code units.  `num` starts at byte 12,
    /// so its UTF-16 col = 10 (units before it) + 1 = 11.
    #[test]
    fn test_process_tree_sitter_tree_request_multibyte() {
        // Source: `x = "🚀"; num = 5`
        // printf 'x = "\xF0\x9F\x9A\x80"; num = 5' | base64
        let request = TreeSitterRequest {
            code_base64: "eCA9ICLwn5qAIjsgbnVtID0gNQ==".to_string(),
            file_encoding: "utf-8".to_string(),
            language: Language::Python,
        };
        let response = process_tree_sitter_tree_request(request);
        assert!(response.errors.is_empty());
        let root = response.result.unwrap();

        /// Depth-first search for a node whose `start.col` matches `expected_col`.
        fn find_col(
            node: &crate::model::tree_sitter_tree_node::ServerTreeSitterNode,
            expected_col: u32,
        ) -> bool {
            if node.start.col == expected_col {
                return true;
            }
            node.children.iter().any(|c| find_col(c, expected_col))
        }

        // `num` starts at byte 12 in `x = "🚀"; num = 5`.
        // UTF-16 units before it: x(1) ' '(1) =(1) ' '(1) "(1) 🚀(2) "(1) ;(1) ' '(1) = 10 → col 11.
        assert!(
            find_col(&root, 11),
            "expected a node with UTF-16 start.col == 11 (position of `num` after 🚀)"
        );

        // Ensure that no node reports col 13 (what the raw byte col + 1 would give for `num`).
        assert!(
            !find_col(&root, 13),
            "no node should report raw byte col 13 — that would indicate the UTF-16 fix is not applied"
        );
    }

    #[test]
    fn test_process_tree_sitter_invalid_base64() {
        let request = TreeSitterRequest {
            code_base64: "we2323423423090909)()(&(*&!@!@=".to_string(),
            file_encoding: "utf-8".to_string(),
            language: Language::Python,
        };
        let response = process_tree_sitter_tree_request(request);
        assert_eq!(
            &ERROR_CODE_NOT_BASE64.to_string(),
            response.errors.get(0).unwrap()
        );
        assert!(response.result.is_none());
    }
}
