use std::collections::HashSet;
use std::fs;
use std::fs::read_to_string;
use std::path::{Path, PathBuf};

use anyhow::Result;
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

use kernel::model::common::Language;
use kernel::model::config_file::PathConfig;
use kernel::model::violation::Violation;

use crate::model::cli_configuration::CliConfiguration;
use crate::model::datadog_api::DiffAwareData;

static FILE_EXTENSIONS_PER_LANGUAGE_LIST: &[(Language, &[&str])] = &[
    (Language::Csharp, &["cs"]),
    (Language::Dockerfile, &["docker", "dockerfile"]),
    (Language::Go, &["go"]),
    (Language::Java, &["java"]),
    (Language::JavaScript, &["js", "jsx"]),
    (Language::Kotlin, &["kt", "kts"]),
    (Language::Python, &["py", "py3"]),
    (Language::Ruby, &["rb"]),
    (Language::Rust, &["rs"]),
    (Language::Swift, &["swift"]),
    (Language::Terraform, &["tf"]),
    (Language::TypeScript, &["ts", "tsx"]),
    (Language::Yaml, &["yml", "yaml"]),
    (Language::Starlark, &["bzl"]),
    (Language::Bash, &["sh", "bash"]),
];

static FILE_EXACT_MATCH_PER_LANGUAGE_LIST: &[(Language, &[&str])] = &[
    (Language::Dockerfile, &["Dockerfile"]),
    (Language::Starlark, &["BUILD", "BUILD.bazel"]),
];

static FILE_PREFIX_PER_LANGUAGE_LIST: &[(Language, &[&str])] =
    &[(Language::Dockerfile, &["Dockerfile"])];

// get all extensions for a language.
fn get_extensions_for_language(language: &Language) -> Option<Vec<String>> {
    for fe in FILE_EXTENSIONS_PER_LANGUAGE_LIST {
        if fe.0 == *language {
            let extensions = fe.1.to_vec();
            return Some(extensions.iter().map(|x| x.to_string()).collect());
        }
    }
    None
}

// if a langauge only match a file for an exact match, return it
fn get_exact_filename_for_language(language: &Language) -> Option<Vec<String>> {
    for fe in FILE_EXACT_MATCH_PER_LANGUAGE_LIST {
        if fe.0 == *language {
            let extensions = fe.1.to_vec();
            return Some(extensions.iter().map(|x| x.to_string()).collect());
        }
    }
    None
}

// get the prefix for a file that needs to be analyzed for a language
fn get_prefix_for_language(language: &Language) -> Option<Vec<String>> {
    for fe in FILE_PREFIX_PER_LANGUAGE_LIST {
        if fe.0 == *language {
            let extensions = fe.1.to_vec();
            return Some(extensions.iter().map(|x| x.to_string()).collect());
        }
    }
    None
}

// Read the .gitignore file in a directory and return the lines that are not commented
// or empty.
// We ignore pattern that start with # (comments) or contains ! (cause repositories
// not being included and totally skipped).
pub fn read_files_from_gitignore_internal(path: &PathBuf) -> Result<Vec<String>> {
    if path.exists() {
        let lines: Vec<String> = read_to_string(path)?
            .lines()
            .map(String::from)
            .filter(|v| !v.starts_with('#'))
            .filter(|v| !v.contains('!'))
            .filter(|v| !v.is_empty())
            .collect();
        return Ok(lines);
    }
    Ok(vec![])
}

pub fn read_files_from_gitignore(source_directory: &str) -> Result<Vec<String>> {
    let gitignore_path = Path::new(source_directory).join(".gitignore");
    read_files_from_gitignore_internal(&gitignore_path)
}

/// get the files to analyze from the directory. This function walks the directory
/// to analyze recursively and gets all the files.
/// if passed, subdirectories_to_analyze are subdirectories within the directory.
pub fn get_files(
    directory: &str,
    subdirectories_to_analyze: Vec<String>,
    path_config: &PathConfig,
) -> Result<Vec<PathBuf>> {
    let mut files_to_return: Vec<PathBuf> = vec![];

    // This is the directory that contains the .git files, we do not need to keep them.
    let git_directory = format!("{}/.git", &directory);

    let directories_to_walk: Vec<String> = if !subdirectories_to_analyze.is_empty() {
        subdirectories_to_analyze
            .iter()
            .map(|p| {
                let sd_str = p.as_str();
                let p = Path::new(directory).join(sd_str);
                p.as_os_str().to_str().unwrap().to_string()
            })
            .collect()
    } else {
        vec![directory.to_string()]
    };

    for directory_to_walk in directories_to_walk {
        for entry in WalkDir::new(directory_to_walk.as_str()) {
            let dir_entry = entry?;
            let entry = dir_entry.path();

            // we only include if this is a file and not a symlink
            // we should NEVER follow symlink for security reason (an attacker could then
            // attempt to add a symlink outside the repo and read content outside of the
            // repo with a custom rule.
            let mut should_include = entry.is_file() && !entry.is_symlink();
            let path_buf = entry.to_path_buf();

            let relative_path_str = path_buf
                .strip_prefix(directory)
                .ok()
                .and_then(|p| p.to_str())
                .ok_or_else(|| anyhow::Error::msg("should get the path"))?;

            // check if the path is allowed by the configuration.
            should_include = should_include && path_config.allows_file(relative_path_str);

            // do not include the git directory.
            if entry.starts_with(git_directory.as_str()) {
                should_include = false;
            }

            if should_include {
                files_to_return.push(entry.to_path_buf());
            }
        }
    }
    Ok(files_to_return)
}

/// try to find if one of the subdirectory used to scan a repository is going outside the
/// repository directory. If yes, this is unsafe, scans outside the repository and should
/// not run.
pub fn are_subdirectories_safe(directory_path: &Path, subdirectories: &[String]) -> bool {
    let directory_canonicalized = directory_path
        .canonicalize()
        .expect("cannot canonicalize repository directory");
    return subdirectories.iter().all(|subdirectory| {
        let new_path = directory_path.join(subdirectory).canonicalize();
        match new_path {
            Err(e) => panic!("error when checking directory {}: {}", subdirectory, e),
            Ok(p) => {
                if !p.starts_with(directory_canonicalized.clone()) {
                    return false;
                }
                true
            }
        }
    });
}

// filter the file according to a list of extensions
fn match_extension(path: &Path, extensions: &[String]) -> bool {
    match path.extension() {
        Some(ext) => match ext.to_str() {
            Some(e) => extensions.contains(&e.to_string().to_lowercase()),
            None => false,
        },
        None => false,
    }
}

// filter a file based on its name
fn match_exact_filename(path: &Path, filename_list: &[String]) -> bool {
    match path.file_name() {
        Some(p) => match p.to_str() {
            Some(s) => filename_list.contains(&s.to_string()),
            None => false,
        },
        None => false,
    }
}

fn match_prefix_filename(path: &Path, prefixes_list: &[String]) -> bool {
    match path.file_name() {
        Some(p) => match p.to_str() {
            Some(s) => prefixes_list.iter().any(|p| s.to_string().starts_with(p)),
            None => false,
        },
        None => false,
    }
}

// filter files to analyze for a language. It will filter the files based on the prefix or suffix.
pub fn filter_files_for_language(files: &[PathBuf], language: &Language) -> Vec<PathBuf> {
    let extensions = get_extensions_for_language(language).unwrap_or_default();
    let exact_matches = get_exact_filename_for_language(language).unwrap_or_default();
    let prefixes = get_prefix_for_language(language).unwrap_or_default();

    if extensions.is_empty() && exact_matches.is_empty() && prefixes.is_empty() {
        return vec![];
    }

    let result = files
        .iter()
        .filter(|p| {
            let extension_match = match_extension(p, &extensions);
            let filename_match = match_exact_filename(p, &exact_matches);
            let prefix_match = match_prefix_filename(p, &prefixes);

            extension_match || filename_match || prefix_match
        })
        .cloned()
        .collect();
    result
}

pub fn filter_files_by_size(files: &[PathBuf], configuration: &CliConfiguration) -> Vec<PathBuf> {
    let max_len_bytes = configuration.max_file_size_kb * 1024;
    return files
        .iter()
        .filter(|f| {
            let metadata = fs::metadata(f);
            let too_big = metadata
                .as_ref()
                .map(|x| x.len() > max_len_bytes)
                .unwrap_or(false);

            if configuration.use_debug && too_big {
                eprintln!(
                    "File {} too big (size {} bytes, max size {} kb ({} bytes))",
                    f.display(),
                    &metadata.map(|x| x.len()).unwrap_or(0),
                    configuration.max_file_size_kb,
                    max_len_bytes
                )
            }

            f.is_file() && !too_big
        })
        .cloned()
        .collect();
}

/// Filter the files to scan for diff-aware scanning.
///  - files is the list of files we should scan (full path on disk)
///  - directory_path is the path of the directory
///  - diff_aware_info is the information we got from our API about the scan to do with the list of files
///    and base sha
/// We return the list of files from the first arguments filtered with the list of files we should effectively
/// scan. The returned list length must always less or equal than the initial list (first argument).
pub fn filter_files_by_diff_aware_info(
    files: &[PathBuf],
    directory_path: &Path,
    diff_aware_info: &DiffAwareData,
) -> Vec<PathBuf> {
    let files_to_scan: HashSet<&str> =
        HashSet::from_iter(diff_aware_info.files.iter().map(|f| f.as_str()));

    return files
        .iter()
        .filter(|f| {
            let p = f
                .strip_prefix(directory_path)
                .unwrap()
                .to_str()
                .expect("path contains non-Unicode characters");

            files_to_scan.contains(p)
        })
        .cloned()
        .collect();
}

/// Generate a fingerprint for a violation that will uniquely identify the violation. The fingerprint is calculated
/// as is
///  SHA2(<file-location-in-repository> - <characters-in-directory> - <content-of-code-line> - <number of characters in line>)
pub fn get_fingerprint_for_violation(
    rule_name: String,
    violation: &Violation,
    repository_root: &Path,
    file: &Path,
    use_debug: bool,
) -> Option<String> {
    let path = repository_root.join(file);
    let filename = file.to_str().unwrap_or("");
    if !path.exists() || !path.is_file() {
        return None;
    }
    let line = violation.start.line as usize;

    match read_to_string(&path) {
        Ok(file_content) => match file_content.lines().nth(line - 1) {
            Some(line_content) => {
                let line_content_stripped = line_content
                    .chars()
                    .filter(|ch| !ch.is_whitespace())
                    .collect::<String>();
                let hash_content = format!(
                    "{}|{}|{}|{}|{}",
                    rule_name,
                    filename,
                    filename.len(),
                    line_content_stripped,
                    line_content_stripped.len()
                );
                let hash = format!("{:x}", Sha256::digest(hash_content.as_bytes()));
                Some(hash)
            }
            None => None,
        },
        Err(_) => {
            if use_debug {
                eprintln!(
                    "Error when trying to read file {}",
                    path.into_os_string().to_str().unwrap_or("")
                );
            }
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};
    use std::env;
    use std::path::Path;

    use kernel::arguments::ArgumentProvider;
    use tempfile::{tempdir, TempDir};

    use kernel::model::common::OutputFormat::Sarif;
    use kernel::model::common::Position;
    use kernel::model::rule::{RuleCategory, RuleSeverity};
    use kernel::path_restrictions::PathRestrictions;

    use super::*;

    #[test]
    fn get_gitignore_exists() {
        let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.push("resources/test/gitignore/test1");
        let file_list = read_files_from_gitignore_internal(&d);
        assert!(file_list.is_ok());
        let fl = file_list.unwrap();
        assert_eq!(85, fl.len());
        // check it contains the values of the file
        assert!(fl.contains(&"ddtrace/appsec/_ddwaf.cpp".to_string()));
        // make sure it does not contains lines with !
        assert!(!fl.contains(&"!.env".to_string()));
        assert_eq!(
            0,
            fl.iter()
                .filter(|v| v.starts_with("#"))
                .collect::<Vec<&String>>()
                .len()
        )
    }

    #[test]
    fn get_fingerprint_for_violation_success() {
        let d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let violation = Violation {
            start: Position { line: 10, col: 1 },
            end: Position { line: 12, col: 1 },
            message: "something bad happened".to_string(),
            severity: RuleSeverity::Notice,
            category: RuleCategory::Performance,
            fixes: vec![],
        };
        let directory_string = d.into_os_string().into_string().unwrap();
        let fingerprint = get_fingerprint_for_violation(
            "my_rule".to_string(),
            &violation,
            Path::new(directory_string.as_str()),
            Path::new("resources/test/gitignore/test1"),
            false,
        );
        assert!(!fingerprint.is_none());
        assert_eq!(
            fingerprint.unwrap(),
            "882d2eca8a353641ecfc71d4befb5dcb115a05b543dce6b7fa8a55cce62982db".to_string()
        );

        let fingerprint_unknown_file = get_fingerprint_for_violation(
            "my_rule".to_string(),
            &violation,
            Path::new(directory_string.as_str()),
            Path::new("path/does/not/exists"),
            false,
        );
        assert!(fingerprint_unknown_file.is_none());
    }

    /// same violation, same location, just a different rule id: the fingerprint should
    /// be different.
    #[test]
    fn get_fingerprint_different_by_rule() {
        let d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let path = "resources/test/gitignore/test1";

        let violation = Violation {
            start: Position { line: 10, col: 1 },
            end: Position { line: 12, col: 1 },
            message: "something bad happened".to_string(),
            severity: RuleSeverity::Notice,
            category: RuleCategory::Performance,
            fixes: vec![],
        };
        let directory_string = d.into_os_string().into_string().unwrap();

        let fingerprint1 = get_fingerprint_for_violation(
            "rule1".to_string(),
            &violation,
            Path::new(directory_string.as_str()),
            Path::new(path),
            false,
        )
        .unwrap();
        let fingerprint2 = get_fingerprint_for_violation(
            "rule1".to_string(),
            &violation,
            Path::new(directory_string.as_str()),
            Path::new(path),
            false,
        )
        .unwrap();
        let fingerprint3 = get_fingerprint_for_violation(
            "rule2".to_string(),
            &violation,
            Path::new(directory_string.as_str()),
            Path::new(path),
            false,
        )
        .unwrap();
        assert_eq!(&fingerprint1, &fingerprint2);
        assert_ne!(&fingerprint1, &fingerprint3);
        assert_ne!(&fingerprint2, &fingerprint3);
    }

    #[test]
    fn test_are_subdirectories_safe() {
        // Create temporary directories and have a directory called plop inside.
        let directory_dir = env::temp_dir();
        let plop_dir = directory_dir.join("plop");
        if !Path::exists(plop_dir.as_path()) {
            fs::create_dir(&plop_dir).expect("can create dir");
        }

        let directory = directory_dir.as_path();
        assert!(!are_subdirectories_safe(directory, &["../".to_string()]));
        assert!(are_subdirectories_safe(directory, &vec![]));
        assert!(are_subdirectories_safe(directory, &["plop".to_string()]));

        fs::remove_dir(plop_dir).expect("cannot remove dir")
    }

    /// Filter files bigger than one kilobyte and make sure files
    /// less than one kilobyte are not being filtered.
    #[test]
    fn test_filter_files_by_size() {
        let mut files1 = vec![];
        let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.push("resources/test/test_files_by_size/versions.json");
        files1.push(d);
        let cli_configuration = CliConfiguration {
            use_debug: true,
            use_configuration_file: true,
            ignore_gitignore: true,
            source_directory: "bla".to_string(),
            source_subdirectories: vec![],
            path_config: PathConfig::default(),
            rules_file: None,
            output_format: Sarif, // SARIF or JSON
            output_file: "foo".to_string(),
            num_cpus: 2, // of cpus to use for parallelism
            rules: vec![],
            path_restrictions: PathRestrictions::default(),
            argument_provider: ArgumentProvider::new(),
            max_file_size_kb: 1,
            use_staging: false,
            show_performance_statistics: false,
            ignore_generated_files: false,
        };
        assert_eq!(0, filter_files_by_size(&files1, &cli_configuration).len());

        let mut files2 = vec![];
        let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.push("resources/test/test_files_by_size/versions-empty.json");
        files2.push(d);
        assert_eq!(1, filter_files_by_size(&files2, &cli_configuration).len());
    }

    /// Filter files based on diff-aware returned files
    #[test]
    fn test_filter_files_by_diff_aware_info() {
        let mut files = vec![];
        files.push(PathBuf::from("/path/to/repo/path/to/file1.py"));
        files.push(PathBuf::from("/path/to/repo/path/to/file2.py"));

        let repository_path = Path::new("/path/to/repo/");

        let diff_aware_info = DiffAwareData {
            files: vec!["path/to/file2.py".to_string()],
            base_sha: "9f3f1e85b0b180a753612db3c0abe2c775b1588b".to_string(),
        };

        let res = filter_files_by_diff_aware_info(&files, repository_path, &diff_aware_info);
        assert_eq!(1, res.len());
        assert_eq!(
            "/path/to/repo/path/to/file2.py".to_string(),
            res.get(0).unwrap().to_str().unwrap().to_string()
        );
    }

    #[test]
    fn get_gitignore_do_not_exists() {
        let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.push("resources/test/gitignore/test-do-not-exists");
        let file_list = read_files_from_gitignore_internal(&d);
        assert!(file_list.is_ok());
        let fl = file_list.unwrap();
        assert!(fl.is_empty());
    }

    struct TestDir {
        dir: TempDir,
    }

    impl TestDir {
        fn new() -> Self {
            TestDir {
                dir: tempdir().unwrap(),
            }
        }

        fn base_path(&self) -> String {
            self.dir.path().display().to_string()
        }

        fn add_file(&self, path: &str) {
            let full_path = self.dir.path().join(path);
            if let Some(dir) = full_path.parent() {
                fs::create_dir_all(dir).unwrap();
            }
            fs::File::create(full_path).unwrap();
        }
    }

    macro_rules! assert_contains_files {
        ($basepath:expr, $files:expr, $wanted:expr) => {
            let base_path = Path::new($basepath);
            let actual_set: HashSet<&PathBuf> = HashSet::from_iter($files.iter());
            for name in $wanted {
                assert!(
                    actual_set.contains(&base_path.join(name)),
                    "file {} not found in list when it was expected",
                    name
                );
            }
        };
    }

    macro_rules! assert_not_contains_files {
        ($basepath:expr, $files:expr, $wanted:expr) => {
            let base_path = Path::new($basepath);
            let actual_set: HashSet<&PathBuf> = HashSet::from_iter($files.iter());
            for name in $wanted {
                assert!(
                    !actual_set.contains(&base_path.join(name)),
                    "file {} found in list when it was not expected",
                    name
                );
            }
        };
    }

    // make sure we can get the list of rules from a directory and that the
    // ignore-paths correctly works when we pass a glob.
    #[test]
    fn get_list_of_files_with_path_config() {
        let test_dir = TestDir::new();
        test_dir.add_file("src/a/main.rs");
        test_dir.add_file("src/a/other.rs");
        test_dir.add_file("src/b/main.rs");
        test_dir.add_file("test/a/main.rs");
        test_dir.add_file("test/a/other.rs");
        test_dir.add_file("test/b/main.rs");
        let base_path = test_dir.base_path();

        // first, we get the list of files without any path to ignore
        let empty_config = PathConfig::default();
        let files = get_files(&base_path, vec![], &empty_config).unwrap();
        assert_contains_files!(
            &base_path,
            files,
            [
                "src/a/main.rs",
                "src/b/main.rs",
                "test/a/main.rs",
                "test/a/other.rs",
                "test/b/main.rs",
            ]
        );

        // now, we add one glob pattern to ignore
        let path_config = PathConfig {
            ignore: vec!["src/**/main.rs".to_string().into()],
            only: None,
        };
        let files = get_files(&base_path, vec![], &path_config).unwrap();
        assert_contains_files!(
            &base_path,
            files,
            [
                "src/a/other.rs",
                "test/a/main.rs",
                "test/a/other.rs",
                "test/b/main.rs"
            ]
        );
        assert_not_contains_files!(&base_path, files, ["src/a/main.rs", "src/b/main.rs"]);

        // now, we add one path prefix to ignore
        let path_config = PathConfig {
            ignore: vec!["src/a".to_string().into()],
            only: None,
        };
        let files = get_files(&base_path, vec![], &path_config).unwrap();
        assert_contains_files!(&base_path, files, ["src/b/main.rs", "test/a/main.rs",]);
        assert_not_contains_files!(&base_path, files, ["src/a/main.rs", "src/a/other.rs"]);

        // now we add one glob pattern to require
        let path_config = PathConfig {
            ignore: vec![],
            only: Some(vec!["**/other.rs".to_string().into()]),
        };
        let files = get_files(&base_path, vec![], &path_config).unwrap();
        assert_contains_files!(&base_path, files, ["src/a/other.rs", "test/a/other.rs"]);
        assert_not_contains_files!(&base_path, files, ["src/a/main.rs", "test/a/main.rs"]);

        // now we add one glob path prefix to require
        let path_config = PathConfig {
            ignore: vec![],
            only: Some(vec!["src/a".to_string().into()]),
        };
        let files = get_files(&base_path, vec![], &path_config).unwrap();
        assert_contains_files!(&base_path, files, ["src/a/main.rs", "src/a/other.rs"]);
        assert_not_contains_files!(&base_path, files, ["src/b/main.rs", "test/a/main.rs"]);
    }

    #[test]
    fn get_files_with_subdirectory() {
        let current_path = std::env::current_dir().unwrap();
        let subdirectory = Path::new("src").join("sarif");

        // first, we get the list of files without any path to ignore
        let files = get_files(
            current_path.display().to_string().as_str(),
            vec![subdirectory.into_os_string().into_string().unwrap()],
            &PathConfig::default(),
        );

        assert_eq!(2, files.unwrap().len());
    }

    // check that we have the correct number of extensions for each language we support.
    #[test]
    fn get_extensions_for_language_all_languages() {
        let mut extensions_per_languages: HashMap<Language, usize> = HashMap::new();
        extensions_per_languages.insert(Language::JavaScript, 2);
        extensions_per_languages.insert(Language::Python, 2);
        extensions_per_languages.insert(Language::Rust, 1);
        extensions_per_languages.insert(Language::TypeScript, 2);
        extensions_per_languages.insert(Language::Dockerfile, 2);
        extensions_per_languages.insert(Language::Yaml, 2);
        extensions_per_languages.insert(Language::Starlark, 1);
        extensions_per_languages.insert(Language::Bash, 2);

        for (l, e) in extensions_per_languages {
            assert_eq!(
                get_extensions_for_language(&l)
                    .expect("have extensions")
                    .len(),
                e
            );
        }
    }

    #[test]
    fn test_filter_files_for_language_suffix() {
        let current_path = std::env::current_dir().unwrap();

        let files = get_files(
            current_path.display().to_string().as_str(),
            vec![],
            &PathConfig::default(),
        );
        assert!(files.is_ok());
        let files = &files.unwrap();
        assert_eq!(
            0,
            filter_files_for_language(files, &Language::TypeScript).len()
        );
        assert_ne!(0, filter_files_for_language(files, &Language::Rust).len());
        assert_eq!(
            1,
            filter_files_for_language(
                &[PathBuf::from("path").join(PathBuf::from("foobar.Dockerfile"))],
                &Language::Dockerfile
            )
            .len()
        );
    }

    #[test]
    fn test_filter_files_for_language_with_prefix() {
        assert_eq!(
            1,
            filter_files_for_language(
                &[PathBuf::from("path").join(PathBuf::from("Dockerfile.foobar"))],
                &Language::Dockerfile
            )
            .len()
        );
        assert_eq!(
            0,
            filter_files_for_language(
                &[PathBuf::from("path").join(PathBuf::from("Dock3rfile.foobar"))],
                &Language::Dockerfile
            )
            .len()
        );
    }

    #[test]
    fn test_filter_files_for_language_with_exact_match() {
        assert_eq!(
            1,
            filter_files_for_language(
                &[PathBuf::from("path").join(PathBuf::from("Dockerfile"))],
                &Language::Dockerfile
            )
            .len()
        );
        assert_eq!(
            0,
            filter_files_for_language(
                &[PathBuf::from("path").join(PathBuf::from("Dock3rfile"))],
                &Language::Dockerfile
            )
            .len()
        );
    }
}
