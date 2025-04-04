use anyhow::format_err;
use std::fs;
use std::path::Path;

/// Read a file and if the file has some invalid UTF-8 characters, it returns a string with invalid
/// characters.
pub fn read_file(path: &Path) -> anyhow::Result<String> {
    let bytes = fs::read(path).map_err(|e| anyhow::anyhow!("cannot read file: {}", e))?;
    match String::from_utf8(bytes) {
        Ok(s) => Ok(s),
        Err(e) => {
            let bytes = e.into_bytes();
            Ok(String::from_utf8_lossy(&bytes).to_string())
        }
    }
}
