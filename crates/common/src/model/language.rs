use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::Path;

#[derive(Copy, Clone, Deserialize, Debug, Serialize, Eq, Hash, PartialEq)]
pub enum Language {
    #[serde(rename = "CSHARP")]
    Csharp,
    #[serde(rename = "DART")]
    Dart,
    #[serde(rename = "DOCKERFILE")]
    Dockerfile,
    #[serde(rename = "ELIXIR")]
    Elixir,
    #[serde(rename = "GO")]
    Go,
    #[serde(rename = "JAVA")]
    Java,
    #[serde(rename = "JAVASCRIPT")]
    JavaScript,
    #[serde(rename = "JSON")]
    Json,
    #[serde(rename = "KOTLIN")]
    Kotlin,
    #[serde(rename = "PYTHON")]
    Python,
    #[serde(rename = "RUBY")]
    Ruby,
    #[serde(rename = "RUST")]
    Rust,
    #[serde(rename = "SWIFT")]
    Swift,
    #[serde(rename = "TERRAFORM")]
    Terraform,
    #[serde(rename = "TYPESCRIPT")]
    TypeScript,
    #[serde(rename = "YAML")]
    Yaml,
    #[serde(rename = "STARLARK")]
    Starlark,
    #[serde(rename = "BASH")]
    Bash,
    PHP,
    #[serde(rename = "MARKDOWN")]
    Markdown,
    #[serde(rename = "APEX")]
    Apex,
    R,
    SQL,
}

#[allow(dead_code)]
pub static ALL_LANGUAGES: &[Language] = &[
    Language::Csharp,
    Language::Dart,
    Language::Dockerfile,
    Language::Go,
    Language::Java,
    Language::JavaScript,
    Language::Json,
    Language::Kotlin,
    Language::Python,
    Language::Ruby,
    Language::Rust,
    Language::Swift,
    Language::TypeScript,
    Language::Terraform,
    Language::Yaml,
    Language::Starlark,
    Language::Bash,
    Language::PHP,
    Language::Markdown,
    Language::Apex,
    Language::R,
    Language::SQL,
];

impl fmt::Display for Language {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Csharp => "c#",
            Self::Dart => "dart",
            Self::Dockerfile => "dockerfile",
            Self::Go => "go",
            Self::Elixir => "elixir",
            Self::Java => "java",
            Self::JavaScript => "javascript",
            Self::Json => "json",
            Self::Kotlin => "kotlin",
            Self::Python => "python",
            Self::Ruby => "ruby",
            Self::Rust => "rust",
            Self::Swift => "swift",
            Self::Terraform => "terraform",
            Self::TypeScript => "typescript",
            Self::Yaml => "yaml",
            Self::Starlark => "starlark",
            Self::Bash => "bash",
            Self::PHP => "php",
            Self::Markdown => "markdown",
            Self::Apex => "apex",
            Self::R => "r",
            Self::SQL => "sql",
        };
        write!(f, "{s}")
    }
}

pub static FILE_EXTENSIONS_PER_LANGUAGE_LIST: &[(Language, &[&str])] = &[
    (Language::Csharp, &["cs"]),
    (Language::Dart, &["dart"]),
    (Language::Dockerfile, &["docker", "dockerfile"]),
    (Language::Elixir, &["ex", "exs"]),
    (Language::Go, &["go"]),
    (Language::Java, &["java"]),
    (Language::JavaScript, &["js", "jsx", "mjs", "cjs"]),
    (Language::Json, &["json"]),
    (Language::Kotlin, &["kt", "kts"]),
    (Language::Python, &["py", "py3"]),
    (Language::Ruby, &["rb"]),
    (Language::Rust, &["rs"]),
    (Language::Swift, &["swift"]),
    (Language::Terraform, &["tf"]),
    (Language::TypeScript, &["ts", "tsx", "mts", "cts"]),
    (Language::Yaml, &["yml", "yaml"]),
    (Language::Starlark, &["bzl"]),
    (Language::Bash, &["sh", "bash"]),
    (Language::PHP, &["php"]),
    (Language::Markdown, &["md", "mdc"]),
    (Language::Apex, &["cls"]),
    (Language::R, &["r"]),
    (Language::SQL, &["sql"]),
];

pub static FILE_EXACT_MATCH_PER_LANGUAGE_LIST: &[(Language, &[&str])] = &[
    (Language::Dockerfile, &["Dockerfile"]),
    (Language::Starlark, &["BUILD", "BUILD.bazel"]),
];

pub static FILE_PREFIX_PER_LANGUAGE_LIST: &[(Language, &[&str])] =
    &[(Language::Dockerfile, &["Dockerfile"])];

// get all extensions for a language.
pub fn get_extensions_for_language(language: &Language) -> Option<&'static [&'static str]> {
    FILE_EXTENSIONS_PER_LANGUAGE_LIST
        .iter()
        .find(|fe| fe.0 == *language)
        .map(|fe| fe.1)
}

// if a language only match a file for an exact match, return it
pub fn get_exact_filename_for_language(language: &Language) -> Option<&'static [&'static str]> {
    FILE_EXACT_MATCH_PER_LANGUAGE_LIST
        .iter()
        .find(|fe| fe.0 == *language)
        .map(|fe| fe.1)
}

// get the prefix for a file that needs to be analyzed for a language
pub fn get_prefix_for_language(language: &Language) -> Option<&'static [&'static str]> {
    FILE_PREFIX_PER_LANGUAGE_LIST
        .iter()
        .find(|fe| fe.0 == *language)
        .map(|fe| fe.1)
}

// filter the file according to a list of extensions
pub fn match_extension(path: &Path, extensions: &[&str]) -> bool {
    match path.extension() {
        Some(ext) => match ext.to_str() {
            Some(e) => extensions.iter().any(|x| x.eq_ignore_ascii_case(e)),
            None => false,
        },
        None => false,
    }
}

// filter a file based on its name
pub fn match_exact_filename(path: &Path, filename_list: &[&str]) -> bool {
    match path.file_name() {
        Some(p) => match p.to_str() {
            Some(s) => filename_list.contains(&s),
            None => false,
        },
        None => false,
    }
}

/// A `.dockerignore` file (e.g. `Dockerfile.foobar.dockerignore`) shares the `Dockerfile` prefix
/// but is not itself a Dockerfile, so it is excluded here rather than in each caller — this is
/// the single place `get_language_for_file` and `filter_files_for_language` both go through for
/// prefix matching, so they can't disagree on it.
pub fn match_prefix_filename(path: &Path, prefixes_list: &[&str]) -> bool {
    match path.file_name() {
        Some(p) => match p.to_str() {
            Some(s) => {
                if s.ends_with("dockerignore") {
                    return false;
                }
                prefixes_list.iter().any(|p| s.starts_with(p))
            }
            None => false,
        },
        None => false,
    }
}

/// Find the language for a given file.
pub fn get_language_for_file(path: &Path) -> Option<Language> {
    // match for extensions (myfile.c, myfile.php, etc).
    for (language, extensions) in FILE_EXTENSIONS_PER_LANGUAGE_LIST {
        if match_extension(path, extensions) {
            return Some(*language);
        }
    }

    // match for exact match (e.g. BUILD.bazel, Dockerfile, etc)
    for (language, filenames) in FILE_EXACT_MATCH_PER_LANGUAGE_LIST {
        if match_exact_filename(path, filenames) {
            return Some(*language);
        }
    }

    // match for prefix (e.g. Dockerfile.something)
    for (language, prefixes) in FILE_PREFIX_PER_LANGUAGE_LIST {
        if match_prefix_filename(path, prefixes) {
            return Some(*language);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::path::PathBuf;

    // check that we have the correct number of extensions for each language we support.
    #[test]
    fn get_extensions_for_language_all_languages() {
        let mut extensions_per_languages: HashMap<Language, usize> = HashMap::new();
        extensions_per_languages.insert(Language::JavaScript, 4);
        extensions_per_languages.insert(Language::Kotlin, 2);
        extensions_per_languages.insert(Language::Python, 2);
        extensions_per_languages.insert(Language::Rust, 1);
        extensions_per_languages.insert(Language::TypeScript, 4);
        extensions_per_languages.insert(Language::Dockerfile, 2);
        extensions_per_languages.insert(Language::Yaml, 2);
        extensions_per_languages.insert(Language::Starlark, 1);
        extensions_per_languages.insert(Language::Bash, 2);
        extensions_per_languages.insert(Language::PHP, 1);
        extensions_per_languages.insert(Language::Markdown, 2);
        extensions_per_languages.insert(Language::Apex, 1);
        extensions_per_languages.insert(Language::R, 1);
        extensions_per_languages.insert(Language::SQL, 1);

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
    fn test_get_language_for_file() {
        // extension Java
        assert_eq!(
            get_language_for_file(&PathBuf::from("path/to/foo.java")),
            Some(Language::Java)
        );

        // extension Markdown
        assert_eq!(
            get_language_for_file(&PathBuf::from("path/to/foo.md")),
            Some(Language::Markdown)
        );
        assert_eq!(
            get_language_for_file(&PathBuf::from("path/to/foo.mdc")),
            Some(Language::Markdown)
        );

        // exact filename
        assert_eq!(
            get_language_for_file(&PathBuf::from("BUILD.bazel")),
            Some(Language::Starlark)
        );

        // prefix
        assert_eq!(
            get_language_for_file(&PathBuf::from("Dockerfile.foobar")),
            Some(Language::Dockerfile)
        );

        // prefix
        assert_eq!(
            get_language_for_file(&PathBuf::from("Dockerfile.foobar.dockerignore")),
            None
        );

        // none
        assert_eq!(get_language_for_file(&PathBuf::from("wefwefwef")), None);
    }
}
