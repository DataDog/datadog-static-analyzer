// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::analysis::tree_sitter::get_tree;
use crate::model::common::Language;
use std::path::Path;
use std::sync::LazyLock;

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
    if FILENAME_CONVENTION_GLOB.is_match(file_path) {
        return true;
    }
    // 2. Language-based detection via parsing imports:
    has_test_like_import(language, code, pre_parsed_tree)
}

/// A shorthand to build a [`Globset`] when the inputs are guaranteed to be valid paths.
///
/// # Panics
/// Panics if any path isn't valid.
fn build_globset<T: AsRef<str>>(globs: &[T]) -> globset::GlobSet {
    let mut builder = globset::GlobSetBuilder::new();

    for pattern in globs {
        let glob = globset::GlobBuilder::new(pattern.as_ref())
            .literal_separator(true)
            .build()
            .expect("pattern should be valid");
        builder.add(glob);
    }

    builder.build().expect("globset should be valid")
}

/// Detects common conventions used to name test files.
static FILENAME_CONVENTION_GLOB: LazyLock<globset::GlobSet> = LazyLock::new(|| {
    // Detection logic:
    // 1. Any file with a parent folder from a list of common names:
    let folder_names = [
        "test",
        "tests",
        "spec",
        "specs",
        "testcases",
        "testing",
        "__test__",
        "__tests__",
    ];
    let parent_folder_globs = folder_names
        .into_iter()
        .map(|folder| format!("**/{folder}/**/*"))
        .collect::<Vec<_>>();
    // 2. Any filename containing ".test." or ".tests."
    //    While this may have some false detections, this is used to detect a filename name
    //    ending in something like `.test.js` while only using glob syntax.
    let filename_globs = ["**/*[_.]{test,tests,spec,specs}.*"]
        .into_iter()
        .map(String::from)
        .collect::<Vec<_>>();

    build_globset(&[parent_folder_globs, filename_globs].concat())
});

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

#[cfg(test)]
mod cfg_test_tests {
    use super::is_test_file;
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
}
