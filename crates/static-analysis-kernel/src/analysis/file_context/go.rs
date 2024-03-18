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
                package_alias = Some(code.get(start..end).unwrap().to_string());
            }

            // The package name includes the quotes. We do not want to capture the quotes, we only want
            // to capture the package name. For this reason, we need to play with -1/+1 with the index.
            if capture.index == 1 {
                package_name = Some(code.get(start + 1..end - 1).unwrap().to_string());
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

#[cfg(test)]
mod tests {
    use crate::analysis::file_context::common::{get_file_context, FileContext};
    use crate::analysis::tree_sitter::get_tree;
    use crate::model::common::Language;

    #[test]
    fn test_get_file_context_go() {
        let code = r#"
import (
    "math/rand"
    "fmt"
    crand1 "crypto/rand"
    crand2 "crypto/rand"
    foo "fmt"
)
        "#;

        let tree = get_tree(code, &Language::Go).unwrap();

        let file_context_go = match get_file_context(&tree, &Language::Go, &code.to_string()) {
            FileContext::Go(go) => go,
            _ => panic!("unreachable"),
        };

        assert_eq!((&(file_context_go).packages).len(), 3);
        assert!(
            (&(file_context_go)
                .packages
                .contains(&"math/rand".to_string()))
        );
        assert!((&(file_context_go).packages.contains(&"fmt".to_string())));
        assert!(
            (&(file_context_go)
                .packages
                .contains(&"crypto/rand".to_string()))
        );
        assert_eq!((&(file_context_go).packages_aliased).len(), 5);
        assert_eq!(
            (file_context_go).packages_aliased.get("crand1").unwrap(),
            "crypto/rand"
        );
        assert_eq!(
            (file_context_go).packages_aliased.get("rand").unwrap(),
            "math/rand"
        );
        assert_eq!(
            (file_context_go).packages_aliased.get("foo").unwrap(),
            "fmt"
        );
        assert_eq!(
            (file_context_go).packages_aliased.get("rand").unwrap(),
            "math/rand"
        );
    }
}
