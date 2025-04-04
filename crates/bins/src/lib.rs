use anyhow::format_err;
use std::fs;
use std::path::Path;

/// Read a file and if the file has some invalid UTF-8 characters, it returns a string with invalid
/// characters.
pub fn read_file(path: &Path) -> anyhow::Result<String> {
    if let Ok(s) = fs::read_to_string(path) {
        return Ok(s);
    }

    if let Ok(bytes) = fs::read(path) {
        return Ok(String::from_utf8_lossy(&bytes).to_string());
    }

    Err(format_err!("cannot read file {}", path.display()))
}
