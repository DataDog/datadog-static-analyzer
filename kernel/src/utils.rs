use base64::engine::general_purpose;
use base64::Engine;

pub const VERSION: &str = "development";

pub fn decode_base64_string(base64_string: String) -> anyhow::Result<String> {
    anyhow::Ok(String::from_utf8(
        general_purpose::STANDARD.decode(base64_string)?,
    )?)
}
