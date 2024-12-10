// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::analysis::tree_sitter::get_tree;
use crate::model::common::Language;
use std::path::Path;

/// Returns `true` if the file is considered to contain unit tests. If not (or a detection
/// could not be verified), `false` is returned.
pub fn is_test_file(
    language: Language,
    code: &str,
    file_path: &Path,
    pre_parsed_tree: Option<&tree_sitter::Tree>,
) -> bool {
    // This function implements a tiered classification:
    //
    // 1. File path heuristic:
    if has_test_like_path(language, file_path) {
        return true;
    }
    // 2. Language-based detection via parsing imports:
    has_test_like_import(language, code, pre_parsed_tree)
}

/// File path globs that conventionally indicate that the contained files are associated with unit tests.
const DEFAULT_PATHS: &[&str] = &[
    "**/test/**/*",
    "**/tests/**/*",
    "**/spec/**/*",
    "**/specs/**/*",
    "**/testcases/**/*",
    "**/testing/**/*",
    "**/__test__/**/*",
    "**/__tests__/**/*",
];

/// File name globs that conventionally indicate that the file contains unit tests.
const DEFAULT_FILENAMES: &[&str] = &["**/*[_.]{test,tests,spec,specs}.*"];

/// Returns a static `LazyLock` [`GlobSet`](globset::GlobSet) according to the provided glob lists.
///
/// # Usage
/// ```rs
/// let detected_filename = "src/folder/router.test.js";
/// let detected_path = "src/tests/router.js";
/// let custom_filename = "src/folder/Check_router.js";
/// let custom_path = "src/checks/router.js";
///
/// let globset = globset_from!([DEFAULT_PATHS, DEFAULT_FILENAMES]);
/// assert!(globset.is_match(detected_filename) && globset.is_match(detected_path));
/// assert!(!globset.is_match(custom_filename) && !globset.is_match(custom_path));
/// let globset = globset_from!([["**/checks/**/*", "**/Check_*"]]);
/// assert!(!globset.is_match(detected_filename) && !globset.is_match(detected_path));
/// assert!(globset.is_match(custom_filename) && globset.is_match(custom_path));
/// ```
macro_rules! globset_from {
    ($patterns:expr) => {{
        use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
        use std::sync::LazyLock;
        static GLOBSET: LazyLock<GlobSet> = LazyLock::new(|| {
            let mut builder = GlobSetBuilder::new();
            for pattern in $patterns[..].iter().map(|s| *s).flatten() {
                let glob = GlobBuilder::new(pattern)
                    .build()
                    .expect("pattern should be valid");
                builder.add(glob);
            }
            builder.build().expect("glob patterns should be valid")
        });

        &GLOBSET
    }};
}

/// Returns `true` if the provided file path is "test-like"--that is, it suggests that the
/// file contains unit tests or is associated with those that do--or `false` if not.
fn has_test_like_path(language: Language, path: &Path) -> bool {
    #[allow(clippy::match_single_binding)]
    let globset = match language {
        _ => globset_from!([DEFAULT_PATHS, DEFAULT_FILENAMES]),
    };
    globset.is_match(path)
}

/// Returns `true` if any imports in the file are "test-like"--that is, that their presence
/// suggests that the source code contains unit tests--or `false` if not.
fn has_test_like_import(
    language: Language,
    code: &str,
    pre_parsed_tree: Option<&tree_sitter::Tree>,
) -> bool {
    let mut new_tree: Option<tree_sitter::Tree> = None;
    let tree = if pre_parsed_tree.is_none() {
        let _ = std::mem::replace(&mut new_tree, get_tree(code, &language));
        new_tree.as_ref()
    } else {
        pre_parsed_tree
    };
    let Some(_tree) = tree else {
        return false;
    };

    // (Not yet implemented).
    #[allow(clippy::match_single_binding)]
    match language {
        _ => false,
    }
}

/// Returns `true` if any of the sequences in the trie are a prefix of the provided `key_iter`.
fn trie_has_prefix<'key, K, V, I, Q>(trie: &sequence_trie::SequenceTrie<K, V>, key_iter: I) -> bool
where
    I: IntoIterator<Item = &'key Q> + 'key,
    K: sequence_trie::TrieKey + std::borrow::Borrow<Q>,
    Q: ?Sized + sequence_trie::TrieKey + 'key,
{
    trie.prefix_iter(key_iter)
        .any(|node| node.value().is_some())
}

#[cfg(test)]
mod cfg_test_tests {
    use super::{is_test_file, trie_has_prefix};
    use crate::model::common::Language;
    use std::path::PathBuf;

    /// For tests where [`Language`] doesn't affect the behavior.
    const UNUSED_LANG: Language = Language::Json;
    /// For tests where the file source code doesn't affect the behavior.
    const UNUSED_CODE: &str = "";

    /// The name of a folder that matches the "parent folder" classifier.
    const TEST_FOLDER: &str = "tests";
    /// An arbitrary folder name that won't match the "parent folder" classifier.
    const NON_TEST_FOLDER: &str = "src";

    /// Converts the provided path strings into paths that use `\` instead of `/` on Windows.
    fn per_os_paths(paths: &[&str]) -> Vec<String> {
        paths
            .iter()
            .map(|path| {
                if cfg!(windows) {
                    path.replace("/", r#"\"#)
                } else {
                    path.to_string()
                }
            })
            .collect::<Vec<_>>()
    }

    /// `is_test_file` detects files underneath parent folders matching a specific name
    #[test]
    fn parent_folder() {
        // Paths using "$NAME" as a meta variable to substitute with `TEST_FOLDER`/`NON_TEST_FOLDER`.
        let paths = per_os_paths(&[
            "$NAME/file.js",
            "f1/f2/$NAME/file.js",
            "$NAME/f3/f4/file.js",
            "f1/f2/$NAME/f3/f4/file.js",
        ]);
        for path in paths {
            let should = PathBuf::from(path.replace("$NAME", TEST_FOLDER));
            assert!(is_test_file(UNUSED_LANG, UNUSED_CODE, &should, None));
            let should_not = PathBuf::from(path.replace("$NAME", NON_TEST_FOLDER));
            assert!(!is_test_file(UNUSED_LANG, UNUSED_CODE, &should_not, None));
        }
    }

    /// `is_test_file` detects files based on filenames
    #[test]
    fn filename() {
        let shoulds = per_os_paths(&[
            &format!("f1/f2/{NON_TEST_FOLDER}/file.test.js"),
            &format!("f1/f2/{NON_TEST_FOLDER}/file_test.js"),
            &format!("f1/f2/{NON_TEST_FOLDER}/file.tests.js"),
            &format!("f1/f2/{NON_TEST_FOLDER}/file_tests.js"),
            "file.test.js",
            ".test.js",
            // ("Limitation": true extensions are not considered)
            "file.test.ext",
        ]);
        let should_nots = per_os_paths(&[
            &format!("f1/f2/{NON_TEST_FOLDER}/test.js"),
            &format!("f1/f2/{NON_TEST_FOLDER}/tests.js"),
            &format!("f1/f2/{NON_TEST_FOLDER}/file_test_run.js"),
            "test.js",
        ]);
        for path_str in shoulds {
            let path = PathBuf::from(path_str);
            assert!(is_test_file(UNUSED_LANG, UNUSED_CODE, &path, None));
        }
        for path_str in should_nots {
            let path = PathBuf::from(path_str);
            assert!(!is_test_file(UNUSED_LANG, UNUSED_CODE, &path, None));
        }
    }

    /// Ensures that [`trie_has_prefix`] can be used for the use case of matching prefixes
    /// within fully-qualified names.
    #[test]
    fn trie_has_prefix_works_for_imports() {
        let imports = ["javax.servlet.jsp", "javax.security.auth.message"];
        let mut trie = sequence_trie::SequenceTrie::<String, ()>::new();
        for import in imports {
            let parts = import.split(".").map(String::from).collect::<Vec<_>>();
            trie.insert(parts.iter(), ());
        }
        // Test cases:
        // 1. Exact match
        // javax.security.auth.message      javax.servlet.jsp
        // ^^^^^^^^^^^^^^^^^^^^^^^^^^^
        assert!(trie_has_prefix(
            &trie,
            "javax.security.auth.message".split(".")
        ));

        // 2. Incomplete match
        // javax.security.auth.message      javax.servlet.jsp
        // ^^^^^^^^^^^^^^^^^^^
        assert!(!trie_has_prefix(&trie, "javax.security.auth".split(".")));

        // 3. Superset
        // javax.security.auth.message      javax.servlet.jsp
        //                                  ^^^^^^^^^^^^^^^^^.jstl.sql
        assert!(trie_has_prefix(
            &trie,
            "javax.servlet.jsp.jstl.sql".split(".")
        ));

        // 4. No match
        // javax.security.auth.message      javax.servlet.jsp
        //                                                            no.sequence.match
        assert!(!trie_has_prefix(&trie, "no.sequence.match".split(".")));
    }
}
