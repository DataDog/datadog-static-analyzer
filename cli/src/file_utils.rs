use crate::model::cli_configuration::CliConfiguration;
use anyhow::Result;
use glob_match::glob_match;
use kernel::model::common::Language;
use std::fs;
use std::fs::read_to_string;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

static FILE_EXTENSIONS_PER_LANGUAGE_LIST: &[(Language, &[&str])] = &[
    (Language::JavaScript, &["js", "jsx"]),
    (Language::Dockerfile, &["docker", "dockerfile"]),
    (Language::Python, &["py", "py3"]),
    (Language::Rust, &["rs"]),
    (Language::TypeScript, &["ts", "tsx"]),
];

static FILE_EXACT_MATCH_PER_LANGUAGE_LIST: &[(Language, &[&str])] =
    &[(Language::Dockerfile, &["Dockerfile"])];

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

// get the files to analyze from the directory. This function walks the directory
// to analyze recursively and gets all the files.
pub fn get_files(directory: &str, paths_to_ignore: &[String]) -> Result<Vec<PathBuf>> {
    let mut files_to_return: Vec<PathBuf> = vec![];

    // This is the directory that contains the .git files, we do not need to keep them.
    let git_directory = format!("{}/.git", &directory);

    for entry in WalkDir::new(directory) {
        let dir_entry = entry?;
        let entry = dir_entry.path();

        // we only include if this is a file and not a symlink
        // we should NEVER follow symlink for security reason (an attacker could then
        // attempt to add a symlink outside the repo and read content outside of the
        // repo with a custom rule.
        let mut should_include = entry.is_file() && !entry.is_symlink();
        let path_buf = entry.to_path_buf();

        // check if the path should be ignored by a glob or not.
        for path_to_ignore in paths_to_ignore {
            // skip empty path to ignore
            if path_to_ignore.is_empty() {
                continue;
            }

            let relative_path_str = path_buf
                .strip_prefix(directory)
                .ok()
                .and_then(|p| p.to_str())
                .ok_or_else(|| anyhow::Error::msg("should get the path"))?;
            if glob_match(path_to_ignore.as_str(), relative_path_str) {
                should_include = false;
            }

            let relative_path_res = path_buf.strip_prefix(directory);

            if let Ok(relative_path) = relative_path_res {
                if relative_path.starts_with(Path::new(path_to_ignore.as_str())) {
                    should_include = false;
                }
            }
        }

        // do not include the git directory.
        if entry.starts_with(git_directory.as_str()) {
            should_include = false;
        }

        if should_include {
            files_to_return.push(entry.to_path_buf());
        }
    }
    Ok(files_to_return)
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
    let extensions = get_extensions_for_language(language).unwrap_or(vec![]);
    let exact_matches = get_exact_filename_for_language(language).unwrap_or(vec![]);
    let prefixes = get_prefix_for_language(language).unwrap_or(vec![]);

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
            let too_big = &metadata
                .as_ref()
                .map(|x| x.len() > max_len_bytes)
                .unwrap_or(false);

            if configuration.use_debug {
                eprintln!(
                    "File {} too big (size {} bytes, max size {} kb)",
                    f.display(),
                    &metadata.map(|x| x.len()).unwrap_or(0),
                    configuration.max_file_size_kb
                )
            }

            f.is_file() && !*too_big
        })
        .cloned()
        .collect();
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernel::model::common::OutputFormat::Sarif;
    use std::collections::HashMap;
    use std::path::Path;

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
            ignore_paths: vec![],
            rules_file: None,
            output_format: Sarif, // SARIF or JSON
            output_file: "foo".to_string(),
            num_cpus: 2, // of cpus to use for parallelism
            rules: vec![],
            max_file_size_kb: 1,
            use_staging: false,
        };
        assert_eq!(0, filter_files_by_size(&files1, &cli_configuration).len());

        let mut files2 = vec![];
        let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.push("resources/test/test_files_by_size/versions-empty.json");
        files2.push(d);
        assert_eq!(1, filter_files_by_size(&files2, &cli_configuration).len());
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

    // make sure we can get the list of rules from a directory and that the
    // ignore-paths correctly works when we pass a glob.
    #[test]
    fn get_list_of_files_with_glob() {
        let current_path = std::env::current_dir().unwrap();
        let file_to_find = Path::new(current_path.display().to_string().as_str())
            .join("src")
            .join("lib.rs");

        // first, we get the list of files without any path to ignore
        let empty_paths_to_ignore = vec![];
        let files = get_files(
            current_path.display().to_string().as_str(),
            &empty_paths_to_ignore,
        );
        assert!(files.is_ok());
        let f = &files.unwrap();
        let find_file: Vec<String> = f
            .iter()
            .filter(|p| p.display().to_string() == file_to_find.display().to_string())
            .map(|p| p.display().to_string())
            .collect();
        assert_eq!(1, find_file.len());

        // now, we add one path to ignore
        let ignore_paths = vec!["**/src/**/lib.rs".to_string()];
        let files = get_files(current_path.display().to_string().as_str(), &ignore_paths);
        assert!(files.is_ok());
        let f = &files.unwrap();
        let find_file: Vec<String> = f
            .iter()
            .filter(|p| p.display().to_string() == file_to_find.display().to_string())
            .map(|p| p.display().to_string())
            .collect();
        assert_eq!(0, find_file.len()); // correctly filtered
    }

    // make sure we can get the list of rules from a directory and that the
    // ignore-paths correctly works when we pass a prefix.
    #[test]
    fn get_list_of_files_with_prefix() {
        let current_path = std::env::current_dir().unwrap();
        let file_to_find = Path::new(current_path.display().to_string().as_str())
            .join("src")
            .join("lib.rs");

        // now, we one path to ignore, we should filter.
        let ignore_paths = vec!["src".to_string()];
        let files = get_files(current_path.display().to_string().as_str(), &ignore_paths);
        assert!(files.is_ok());
        let f = &files.unwrap();
        let find_file: Vec<String> = f
            .iter()
            .filter(|p| p.display().to_string() == file_to_find.display().to_string())
            .map(|p| p.display().to_string())
            .collect();
        assert_eq!(0, find_file.len()); // correctly filtered

        // now, we add the complete path to ignore, we should filter.
        let ignore_paths = vec!["src/lib.rs".to_string()];
        let files = get_files(current_path.display().to_string().as_str(), &ignore_paths);
        assert!(files.is_ok());
        let f = &files.unwrap();
        let find_file: Vec<String> = f
            .iter()
            .filter(|p| p.display().to_string() == file_to_find.display().to_string())
            .map(|p| p.display().to_string())
            .collect();
        assert_eq!(0, find_file.len()); // correctly filtered

        // now, we add another directory that is totally different, we should not filter.
        let ignore_paths = vec!["foo".to_string()];
        let files = get_files(current_path.display().to_string().as_str(), &ignore_paths);
        assert!(files.is_ok());
        let f = &files.unwrap();
        let find_file: Vec<String> = f
            .iter()
            .filter(|p| p.display().to_string() == file_to_find.display().to_string())
            .map(|p| p.display().to_string())
            .collect();
        assert_eq!(1, find_file.len()); // correctly filtered
    }

    // check that we have the correct number of extensions for each language we support.
    #[test]
    fn get_extensions_for_language_all_languages() {
        let mut extensions_per_languages: HashMap<Language, usize> = HashMap::new();
        extensions_per_languages.insert(Language::JavaScript, 2);
        extensions_per_languages.insert(Language::Python, 2);
        extensions_per_languages.insert(Language::Rust, 1);
        extensions_per_languages.insert(Language::TypeScript, 2);

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

        let empty_paths_to_ignore = vec![];
        let files = get_files(
            current_path.display().to_string().as_str(),
            &empty_paths_to_ignore,
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
