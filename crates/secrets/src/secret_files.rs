use lazy_static::lazy_static;
use std::path::Path;

lazy_static! {
    static ref IGNORE_FILENAMES: Vec<&'static str> = vec![
        "go.mod",
        "WORKSPACE",
        "Gopkg.lock",
        "package-lock.json",
        "yarn.lock",
        "repositories.bzl",
        "mirror.cfg",
    ];
    static ref IGNORE_SUFFIXES: Vec<&'static str> =
        vec!["ico", "jpeg", "jpg", "png", "tif", "tiff", "gif"];
}

/// Return true if the file should be ignored, false otherwise.
/// This function is only valid for secrets.
pub fn should_ignore_file_for_secret(path: &Path) -> bool {
    if let Some(ext) = path.extension() {
        if let Some(e) = ext.to_str() {
            if IGNORE_SUFFIXES.contains(&e) {
                return true;
            }
        }
    }
    if let Some(filename) = path.file_name() {
        if let Some(f) = filename.to_str() {
            if IGNORE_FILENAMES.contains(&f) {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_should_ignore_file_for_secret() {
        assert!(should_ignore_file_for_secret(&PathBuf::from(
            "/path/to/file.gif"
        )));
        assert!(!should_ignore_file_for_secret(&PathBuf::from(
            "/path/to/file.py"
        )));
        assert!(should_ignore_file_for_secret(&PathBuf::from(
            "/path/to/go.mod"
        )));
        assert!(should_ignore_file_for_secret(&PathBuf::from(
            "/path/to/repositories.bzl"
        )));
        assert!(should_ignore_file_for_secret(&PathBuf::from(
            "/path/to/yarn.lock"
        )));
    }
}
