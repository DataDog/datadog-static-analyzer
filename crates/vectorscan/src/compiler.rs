// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

pub mod error;
pub use error::CompileError;
mod mode;
pub use mode::Mode;
pub mod pattern;
pub use pattern::{Pattern, PatternBuilder};

/// Formats an escaped hex representation of the bytes of a string.
///
/// # Example
/// * input:  `hello`
/// * output: `\x68\x65\x6C\x6C\x6F`
///
/// Hyperscan will parse input in this format as a literal instead of a regex.
pub fn format_escaped_hex(input: &str) -> String {
    const HEX_CHARS: &[u8; 16] = b"0123456789ABCDEF";

    let mut escaped = String::with_capacity(input.len() * 4);

    for byte in input.as_bytes() {
        let byte = *byte as usize;
        let first = HEX_CHARS[byte >> 4] as char;
        let second = HEX_CHARS[byte & 0x0F] as char;
        escaped.push('\\');
        escaped.push('x');
        escaped.push(first);
        escaped.push(second);
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::format_escaped_hex as escaped;

    #[test]
    fn test_hex_escape_fn() {
        assert_eq!(escaped("ab|c)^"), r#"\x61\x62\x7C\x63\x29\x5E"#);
        assert_eq!(escaped("👋🌎"), r#"\xF0\x9F\x91\x8B\xF0\x9F\x8C\x8E"#);
        assert_eq!(escaped(""), r#""#);
        assert_eq!(escaped("\n 	"), r#"\x0A\x20\x09"#);
        assert_eq!(escaped("\\x68\\x69"), r#"\x5C\x78\x36\x38\x5C\x78\x36\x39"#);
    }
}
