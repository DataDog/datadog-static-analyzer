use anyhow::Result;
use glob_match::glob_match;
use kernel::model::common::Language;
use std::path::PathBuf;
use walkdir::WalkDir;

static FILE_EXTENSIONS_PER_LANGUAGE_LIST: &[(Language, &[&str])] = &[
    (Language::JavaScript, &["js", "jsx"]),
    (Language::Python, &["py", "py3"]),
    (Language::Rust, &["rs"]),
    (Language::TypeScript, &["ts", "tsx"]),
];

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

        // check if the path should be ignored by a glob or not.
        for path_to_ignore in paths_to_ignore {
            let path_buf = entry.to_path_buf();

            let relative_path = path_buf
                .strip_prefix(directory)
                .ok()
                .and_then(|p| p.to_str())
                .ok_or_else(|| anyhow::Error::msg("should get the path"))?;
            if glob_match(path_to_ignore.as_str(), relative_path) {
                should_include = false;
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

// filter files to analyze for a language. It will filter the files based on the prefix or suffix.
pub fn filter_files_for_language(files: &[PathBuf], language: &Language) -> Vec<PathBuf> {
    let extensions_opt = get_extensions_for_language(language);

    if extensions_opt.is_none() {
        return vec![];
    }

    let extensions = extensions_opt.unwrap();

    let result = files
        .iter()
        .filter(|p| match p.extension() {
            Some(ext) => match ext.to_str() {
                Some(e) => extensions.contains(&e.to_string()),
                None => false,
            },
            None => false,
        })
        .cloned()
        .collect();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::path::Path;

    // make sure we can get the list of rules from a directory and that the
    // ignore-paths correctly works.
    #[test]
    fn get_list_of_files() {
        let current_path = std::env::current_dir().unwrap();
        println!("current path {}", current_path.display());
        let file_to_find = Path::new(current_path.display().to_string().as_str())
            .join("src")
            .join("lib.rs");
        println!("file to find {}", file_to_find.display().to_string());

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
    fn test_filter_files_for_language() {
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
    }
}
