use crate::constants::{ERROR_CODE_NOT_BASE64, ERROR_CODE_NO_ROOT_NODE};
use crate::model::tree_sitter_tree_node::ServerTreeSitterNode;
use crate::model::tree_sitter_tree_request::TreeSitterRequest;
use crate::model::tree_sitter_tree_response::TreeSitterResponse;
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
        &decoded.as_bytes().len()
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

    if let Some(result) =
        result.map(|tree| map_node(tree.root_node()).map(ServerTreeSitterNode::from))
    {
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
