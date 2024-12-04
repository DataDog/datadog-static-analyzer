// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::model::common::Language;
use std::path::Path;
use std::sync::LazyLock;

/// Returns `true` if the file is considered to contain unit tests. If not (or a detection
/// could not be verified), `false` is returned.
#[allow(dead_code)]
pub fn is_test_file(
    _language: Language,
    _code: &str,
    file_path: &Path,
    _precalculated_tree: Option<&tree_sitter::Tree>,
) -> bool {
    static GLOB_PATTERN: LazyLock<globset::GlobSet> = LazyLock::new(|| {
        let mut builder = globset::GlobSetBuilder::new();
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
        // 2. Any filename containing ".test."
        //    While this may have some false detections, this is used to detect a filename name
        //    ending in something like `.test.js` while only using glob syntax.
        let filename_globs = ["**/*.test.*"]
            .into_iter()
            .map(String::from)
            .collect::<Vec<_>>();

        for pattern in &[parent_folder_globs, filename_globs].concat() {
            let glob = globset::GlobBuilder::new(pattern)
                .literal_separator(true)
                .build()
                .expect("pattern should be valid");
            builder.add(glob);
        }

        builder.build().expect("globset should be valid")
    });

    // This function implements a tiered classification:
    //
    // 1. File path heuristic:
    if GLOB_PATTERN.is_match(file_path) {
        return true;
    }
    // 2. Language-based detection:
    //    (Not yet implemented)
    false
}

#[cfg(test)]
mod tests {
    use crate::classifiers::tests::is_test_file;
    use crate::model::common::Language;
    use std::path::PathBuf;

    /// For tests where [`Language`] doesn't affect the behavior.
    const UNUSED_LANG: Language = Language::Json;
    const UNUSED: &str = "";
    /// The name of a folder that matches the "parent folder" classifier.
    const TEST_FOLDER: &str = "tests";
    /// An arbitrary folder name that won't match the "parent folder" classifier.
    const NON_TEST_FOLDER: &str = "src";

    /// `is_test_file` detects files underneath parent folders matching a specific name
    #[test]
    fn parent_folder() {
        // Paths using "$NAME" as a meta variable to substitute with `TEST_FOLDER`/`NON_TEST_FOLDER`.
        let paths = [
            // Unix
            "$NAME/file.js",
            "f1/f2/$NAME/file.js",
            "$NAME/f3/f4/file.js",
            "f1/f2/$NAME/f3/f4/file.js",
        ];
        for path in paths {
            let path_should = PathBuf::from(path.replace("$NAME", TEST_FOLDER));
            assert!(is_test_file(UNUSED_LANG, UNUSED, &path_should, None));
            let path_should_not = PathBuf::from(path.replace("$NAME", NON_TEST_FOLDER));
            assert!(!is_test_file(UNUSED_LANG, UNUSED, &path_should_not, None));
        }
    }

    /// `is_test_file` detects files underneath parent folders matching a specific name
    #[test]
    #[cfg(windows)]
    fn parent_windows() {
        // Paths using "$NAME" as a meta variable to substitute with `TEST_FOLDER`/`NON_TEST_FOLDER`.
        let paths = [
            // Windows
            r#"$NAME\file.js"#,
            r#"f1\f2\$NAME\file.js"#,
            r#"$NAME\f3\f4\file.js"#,
            r#"f1\f2\$NAME\f3\f4\file.js"#,
        ];
        for path in paths {
            let path_should = PathBuf::from(path.replace("$NAME", TEST_FOLDER));
            assert!(is_test_file(UNUSED_LANG, UNUSED, &path_should, None));
            let path_should_not = PathBuf::from(path.replace("$NAME", NON_TEST_FOLDER));
            assert!(!is_test_file(UNUSED_LANG, UNUSED, &path_should_not, None));
        }
    }

    /// `is_test_file` detects files based on filenames
    #[test]
    fn filename() {
        let shoulds = [
            format!("f1/f2/{NON_TEST_FOLDER}/file.test.js"),
            "file.test.js".to_string(),
            ".test.js".to_string(),
            // ("Limitation": true extensions are not considered)
            "file.test.ext".to_string(),
        ];
        let should_nots = [
            format!("f1/f2/{NON_TEST_FOLDER}/test.js"),
            "test.js".to_string(),
        ];
        for str in shoulds {
            let path = PathBuf::from(str);
            assert!(is_test_file(UNUSED_LANG, UNUSED, &path, None));
        }
        for str in should_nots {
            let path = PathBuf::from(str);
            assert!(!is_test_file(UNUSED_LANG, UNUSED, &path, None));
        }
    }
}
