use crate::analysis::file_context::go::{get_file_context_go, FileContextGo};
use crate::model::common::Language;
use serde::Serialize;
use tree_sitter::Tree;

/// Contains all the context for all languages. When we need to serialize this as a string to execute
/// we use the language-specific structure to do so.
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum FileContext {
    Go(FileContextGo),
    None {},
}

pub fn get_empty_file_context() -> FileContext {
    FileContext::None {}
}

pub fn get_file_context(tree: &Tree, language: &Language, code: &String) -> FileContext {
    if *language == Language::Go {
        return FileContext::Go(get_file_context_go(tree, code));
    }
    get_empty_file_context()
}
