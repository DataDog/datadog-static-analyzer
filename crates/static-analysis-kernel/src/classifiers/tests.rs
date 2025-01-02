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

/// Returns a reference to a static `LazyLock` [`SequenceTrie<String, ()>`](sequence_trie::SequenceTrie)
/// that contains the values in the provided list, split by the provided separator.
///
/// # Usage
/// ```rs
/// let imports_trie = trie_from!(["java.util.Scanner", "java.time.format.TextStyle"], ".")
/// ```
macro_rules! trie_from {
    ($list:expr, $separator:expr) => {{
        use sequence_trie::SequenceTrie;
        use std::sync::LazyLock;
        static TRIE: LazyLock<SequenceTrie<String, ()>> = LazyLock::new(|| {
            let mut trie = SequenceTrie::<String, ()>::new();
            for value in $list {
                let parts = value
                    .split($separator)
                    .map(String::from)
                    .collect::<Vec<_>>();
                trie.insert(parts.iter(), ());
            }
            trie
        });
        &TRIE
    }};
}

/// Returns `true` if the provided file path is "test-like"--that is, it suggests that the
/// file contains unit tests or is associated with those that do--or `false` if not.
fn has_test_like_path(language: Language, path: &Path) -> bool {
    use Language::*;
    let globset = match language {
        Go => globset_from!([&[
            // `go test` required filename
            "**/*_test.go",
            // Conventions:
            "**/mock_*.go",
            "**/*_mock.go",
        ]]),
        Java => globset_from!([DEFAULT_PATHS]),
        Python => globset_from!([
            DEFAULT_PATHS,
            DEFAULT_FILENAMES,
            &[
                // behave: https://behave.readthedocs.io/en/latest/gherkin/#feature-testing-layout
                "**/features/steps/*.py",
                "**/features/environment.py",
                // nose2: https://docs.nose2.io/en/latest/usage.html#naming-tests
                "**/test*.py",
                // pytest: https://docs.pytest.org/en/stable/explanation/goodpractices.html#conventions-for-python-test-discovery
                "**/*test_*.py",
                "**/*_test.py",
            ]
        ]),
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
    use Language::*;
    let mut new_tree: Option<tree_sitter::Tree> = None;
    let tree = if pre_parsed_tree.is_none() {
        let _ = std::mem::replace(&mut new_tree, get_tree(code, &language));
        new_tree.as_ref()
    } else {
        pre_parsed_tree
    };
    let Some(tree) = tree else {
        return false;
    };

    match language {
        Go => {
            use crate::analysis::languages::go;
            const SEPARATOR: &str = "/";
            let imports_trie = trie_from!(
                [
                    // check: https://github.com/go-check/check
                    "github.com/go-check/check",
                    // Ginkgo: https://github.com/onsi/ginkgo
                    "github.com/onsi/ginkgo",
                    // gock: https://github.com/h2non/gock
                    "github.com/h2non/gock",
                    // GoConvey: https://github.com/smartystreets/goconvey
                    "github.com/smartystreets/goconvey",
                    // Gomega: https://github.com/onsi/gomega
                    "github.com/onsi/gomega",
                    // GoMock: https://github.com/golang/mock
                    "github.com/golang/mock",
                    // GoMock: https://github.com/uber-go/mock
                    "go.uber.org/mock",
                    // Pegomock: https://github.com/petergtz/pegomock
                    "github.com/petergtz/pegomock",
                    // testing (standard lib): https://pkg.go.dev/testing
                    "testing",
                    // testify: https://github.com/stretchr/testify
                    "github.com/stretchr/testify",
                ],
                SEPARATOR
            );
            let parsed_imports = go::parse_imports_with_tree(code, tree);
            for import in parsed_imports {
                if trie_has_prefix(imports_trie, import.path.split(SEPARATOR)) {
                    return true;
                }
            }
            false
        }
        Java => {
            use crate::analysis::languages::java;
            const SEPARATOR: &str = ".";
            let imports_trie = trie_from!(
                [
                    // Apache Camel: https://github.com/apache/camel
                    "org.apache.camel.test",
                    // Awaitility: https://github.com/awaitility/awaitility
                    "org.awaitility",
                    // Arquillian: https://github.com/arquillian/arquillian-core
                    "org.jboss.arquillian",
                    // AssertJ: https://github.com/assertj/assertj
                    "org.assertj",
                    // Cucumber: https://github.com/cucumber/cucumber-jvm
                    "io.cucumber",
                    // DBUnit: https://sourceforge.net/projects/dbunit/
                    "org.dbunit",
                    // EasyMock: https://github.com/easymock/easymock
                    "org.easymock",
                    // JBehave: https://github.com/jbehave/jbehave-core/
                    "org.jbehave",
                    // JMH: https://github.com/openjdk/jmh
                    "org.openjdk.jmh",
                    // JUnit: https://github.com/junit-team
                    "org.junit",
                    // Karate: https://github.com/karatelabs/karate
                    "com.intuit.karate",
                    // Mockito: https://github.com/mockito/mockito
                    "org.mockito",
                    // Pact: https://github.com/pact-foundation/pact-jvm
                    "au.com.dius.pact",
                    // Powermock: https://github.com/powermock/powermock
                    "org.powermock",
                    // REST-assured: https://github.com/rest-assured/rest-assured
                    "io.restassured",
                    // Selenium: https://github.com/SeleniumHQ/selenium/tree/trunk/java
                    "org.seleniumhq.selenium",
                    "org.openqa.selenium",
                    // Spock: https://github.com/spockframework/spock
                    "org.spockframework",
                    // Testcontainers: https://github.com/testcontainers/testcontainers-java
                    "org.testcontainers",
                    // TestFX: https://github.com/TestFX/TestFX
                    "org.testfx",
                    // TestNG: https://github.com/testng-team/testng
                    "org.testng",
                    // Wiremock: https://github.com/wiremock/wiremock
                    "com.github.tomakehurst.wiremock",
                ],
                SEPARATOR
            );
            let imports = java::parse_imports_with_tree(code, tree);
            for import in imports {
                if trie_has_prefix(imports_trie, import.package.split(SEPARATOR)) {
                    return true;
                }
            }
            false
        }
        Python => {
            use crate::analysis::languages::python;
            const SEPARATOR: &str = ".";
            let imports_trie = trie_from!(
                [
                    // behave: https://github.com/behave/behave
                    "behave",
                    // Lib/doctest: https://docs.python.org/3/library/doctest.html
                    "doctest",
                    // Hypothesis: https://github.com/HypothesisWorks/hypothesis/tree/master/hypothesis-python
                    "hypothesis",
                    // nox: https://github.com/wntrblm/nox
                    "nox",
                    // pytest: https://github.com/pytest-dev/pytest
                    "pytest",
                    // pytest-bdd: https://github.com/pytest-dev/pytest-bdd
                    "pytest_bdd",
                    // Testify: https://github.com/Yelp/Testify
                    "testify",
                    // Lib/unittest: https://docs.python.org/3/library/unittest.html
                    "unittest",
                    // unittest2: https://pypi.org/project/unittest2/
                    "unittest2",
                ],
                SEPARATOR
            );
            let parsed_imports = python::parse_imports_with_tree(code, tree);
            for import in parsed_imports {
                if import
                    .fully_qualified_name()
                    .is_some_and(|fqn| trie_has_prefix(imports_trie, fqn.split(SEPARATOR)))
                {
                    return true;
                }
            }
            false
        }
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
    use std::path::{Path, PathBuf};

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

    #[test]
    fn language_go() {
        fn source_for(imports: &str) -> String {
            format!(
                "\
package pkg

{imports}
"
            )
        }

        let path_based = per_os_paths(&["f1/f2/router_test.go", "f1/f2/router_mock.go"]);
        for path_str in path_based {
            let path = PathBuf::from(path_str);
            assert!(is_test_file(Language::Go, UNUSED_CODE, &path, None));
        }
        let import_shoulds = &[
            r#"import "testing""#,
            r#"import req "github.com/stretchr/testify/require""#,
        ];
        let import_should_nots = &[r#"import "custom_testing""#];
        for imports in import_shoulds {
            let go_code = source_for(imports);
            assert!(is_test_file(Language::Go, &go_code, Path::new(""), None));
        }
        for imports in import_should_nots {
            let go_code = source_for(imports);
            assert!(!is_test_file(Language::Go, &go_code, Path::new(""), None));
        }
    }

    #[test]
    fn language_java() {
        use Language::Java;
        let shoulds = &[
            "import static org.junit.Assert.assertArrayEquals;",
            "import org.mockito.MockitoAnnotations;",
        ];
        let should_nots = &["import org.springframework.boot.SpringApplication;"];
        for java_code in shoulds {
            assert!(is_test_file(Java, java_code, Path::new(""), None));
        }
        for java_code in should_nots {
            assert!(!is_test_file(Java, java_code, Path::new(""), None));
        }
    }

    #[test]
    fn language_python() {
        use Language::Python;
        let path_based = per_os_paths(&[
            "f1/features/steps/file.py",
            "f1/features/environment.py",
            &format!("f1/f2/{NON_TEST_FOLDER}/testfile.py"),
            &format!("f1/f2/{NON_TEST_FOLDER}/test_router.py"),
            &format!("f1/f2/{NON_TEST_FOLDER}/router_test.py"),
        ]);
        for path_str in path_based {
            let path = PathBuf::from(path_str);
            assert!(is_test_file(Python, UNUSED_CODE, &path, None));
        }

        let import_shoulds = &[
            "import unittest",
            "from pytest import feature",
            "from pytest_bdd.parser import Feature",
        ];
        let import_should_nots = &["import customtestlib"];
        for py_code in import_shoulds {
            assert!(is_test_file(Python, py_code, Path::new(""), None));
        }
        for py_code in import_should_nots {
            assert!(!is_test_file(Python, py_code, Path::new(""), None));
        }
    }
}
