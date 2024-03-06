use crate::analysis::file_context::go::{get_file_context_go, FileContextGo};
use crate::model::common::Language;
use serde::Serialize;
use tree_sitter::Tree;

/// Contains all the context for all languages. When we need to serialize this as a string to execute
/// we use the language-specific structure to do so.
#[derive(Debug, Serialize)]
pub enum FileContext {
    Go(FileContextGo),
    None,
}

impl FileContext {
    /// Returns the struct injected in the JavaScript of the rule being executed. This just serializes something
    /// for all rules to be executed.
    /// If we cannot generate a valid file context, we return an empty object {}
    pub fn to_json_string(&self) -> String {
        match self {
            FileContext::Go(go) => serde_json::to_string(go).unwrap_or("{}".to_string()),
            _ => "{}".to_string(),
        }
    }
}

pub fn get_empty_file_context() -> FileContext {
    FileContext::None
}

pub fn get_file_context(tree: &Tree, language: &Language, code: &String) -> FileContext {
    if *language == Language::Go {
        return FileContext::Go(get_file_context_go(tree, code));
    }
    get_empty_file_context()
}
