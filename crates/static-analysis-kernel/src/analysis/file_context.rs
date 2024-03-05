use crate::analysis::tree_sitter::get_tree_sitter_language;
use crate::model::common::Language;
use derive_builder::Builder;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use tree_sitter::{Query, QueryCursor, Tree};

/// Structure for the file context that is specific to Go.
#[derive(Default, Serialize, Builder, Debug, Clone)]
pub struct FileContextGo {
    pub packages: Vec<String>,
    pub packages_aliased: HashMap<String, String>,
}

/// Contains all the context for all languages. When we need to serialize this as a string to execute
/// we use the language-specific structure to do so.
#[derive(Builder, Debug)]
pub struct FileContext {
    pub file_context_go: Option<FileContextGo>,
    pub language: Option<Language>,
}

impl FileContext {
    /// Returns the struct injected in the JavaScript of the rule being executed. This just serializes something
    /// for all rules to be executed.
    /// If we cannot generate a valid file context, we return an empty object {}
    pub fn to_json_string(&self) -> String {
        match self.language {
            Some(Language::Go) => {
                if let Some(file_context_go) = &self.file_context_go {
                    serde_json::to_string(file_context_go).unwrap()
                } else {
                    "{}".to_string()
                }
            }
            _ => "{}".to_string(),
        }
    }
}

/// Get the context for Go. It takes the tree sitter tree, and get all the necessary artifacts to build the context.
pub fn get_file_context_go(tree: &Tree, code: &String) -> FileContextGo {
    let mut packages_list: HashSet<String> = HashSet::new();
    let mut packages_aliased: HashMap<String, String> = HashMap::new();

    // Query to get all the packages and their potential aliases. The first capture is the potential alias,
    // the second capture is the name of the package.
    let query_string = r#"
(import_spec
    name: (_)? @name
    path: (_) @package
)
    "#;
    let query = Query::new(&tree.language(), query_string).unwrap();

    let mut query_cursor = QueryCursor::new();
    let query_result = query_cursor.matches(&query, tree.root_node(), code.as_bytes());
    for query_match in query_result {
        let mut package_name: Option<String> = None;
        let mut package_alias: Option<String> = None;

        for capture in query_match.captures {
            let start = capture.node.byte_range().start;
            let end = capture.node.byte_range().end;

            if capture.index == 0 {
                let str = code
                    .chars()
                    .skip(start)
                    .take(end - start)
                    .collect::<String>();
                package_alias = Some(str);
            }

            // The package name includes the quotes. We do not want to capture the quotes, we only want
            // to capture the package name. For this reason, we need to play with -1/+1 with the index.
            if capture.index == 1 {
                let str = code
                    .chars()
                    .skip(start + 1)
                    .take(end - start - 2)
                    .collect::<String>();
                package_name = Some(str);
            }
        }

        // always add the package to the list
        if let Some(pkg) = &package_name {
            packages_list.insert(pkg.clone());
        }

        // if we have the alias, add it. If we have only the package name, add the package name as an alias
        // so that we have a simple mapping between package and full qualified name
        match (&package_alias, &package_name) {
            (Some(alias), Some(pkg)) => {
                packages_aliased.insert(alias.clone(), pkg.clone());
            }

            (None, Some(pkg)) => {
                let alias_from_pkg = pkg.split('/').last();
                if let Some(alias) = alias_from_pkg {
                    packages_aliased.insert(alias.to_string(), pkg.clone());
                }
            }

            _ => {}
        }
    }

    FileContextGo {
        packages: packages_list.into_iter().collect::<Vec<String>>(),
        packages_aliased,
    }
}

pub fn get_empty_file_context() -> FileContext {
    FileContext {
        file_context_go: None,
        language: None,
    }
}

pub fn get_file_context(tree: &Tree, code: &String) -> FileContext {
    if tree.language().to_owned() == get_tree_sitter_language(&Language::Go) {
        return FileContext {
            file_context_go: Some(get_file_context_go(tree, code)),
            language: Some(Language::Go),
        };
    }

    get_empty_file_context()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::tree_sitter::get_tree;
    use crate::model::common::Language;

    #[test]
    fn test_get_file_context_go() {
        let code = r#"
import (
    "math/rand"
    crand1 "crypto/rand"
    crand2 "crypto/rand"
)
        "#;

        let tree = get_tree(code, &Language::Go).unwrap();

        let file_context = get_file_context(&tree, &code.to_string());
        assert!(file_context.file_context_go.is_some());
        let file_context_go = file_context.file_context_go.unwrap();

        assert_eq!((&(file_context_go).packages).len(), 2);
        assert_eq!((&(file_context_go).packages_aliased).len(), 3);
        assert_eq!(
            (file_context_go).packages_aliased.get("crand1").unwrap(),
            "crypto/rand"
        );
        assert_eq!(
            (file_context_go).packages_aliased.get("rand").unwrap(),
            "math/rand"
        );
    }
}
