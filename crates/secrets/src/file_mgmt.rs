// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026 Datadog, Inc.

use std::collections::HashSet;

/// Get the line numbers that contain the `no-dd-secrets` directive.
/// Returns a set of line numbers (1-indexed) where the directive appears.
/// Only lines starting with `#no-dd-secrets` or `//no-dd-secrets` (after stripping tabs and spaces) are matched.
pub fn get_lines_to_ignore(code: &str) -> HashSet<u32> {
    const DISABLE_PATTERNS: [&str; 2] = ["#no-dd-secrets", "//no-dd-secrets"];

    let mut lines_to_ignore = HashSet::new();

    for (idx, line) in code.lines().enumerate() {
        // Strip all tabs and spaces from the line
        let stripped_line: String = line
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();

        // Check if the stripped line starts with any of the disable patterns
        for pattern in &DISABLE_PATTERNS {
            if stripped_line.starts_with(pattern) {
                lines_to_ignore.insert((idx + 1) as u32);
                break;
            }
        }
    }

    lines_to_ignore
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_lines_to_ignore_empty() {
        let code = "foo\nbar\nbaz";
        let lines = get_lines_to_ignore(code);
        assert!(lines.is_empty());
    }

    #[test]
    fn test_get_lines_to_ignore_single_line() {
        let code = "foo\n# no-dd-secrets\nbar";
        let lines = get_lines_to_ignore(code);
        assert_eq!(lines.len(), 1);
        assert!(lines.contains(&2));
    }

    #[test]
    fn test_get_lines_to_ignore_multiple_lines() {
        let code = "foo\n# no-dd-secrets\nbar\n// no-dd-secrets\nbaz";
        let lines = get_lines_to_ignore(code);
        assert_eq!(lines.len(), 2);
        assert!(lines.contains(&2));
        assert!(lines.contains(&4));
    }

    #[test]
    fn test_get_lines_to_ignore_first_line() {
        let code = "#no-dd-secrets\nfoo\nbar";
        let lines = get_lines_to_ignore(code);
        assert_eq!(lines.len(), 1);
        assert!(lines.contains(&1));
    }

    #[test]
    fn test_get_lines_to_ignore_with_tabs_and_spaces() {
        let code = "foo\n\t  # no-dd-secrets\nbar\n  \t// no-dd-secrets\nbaz";
        let lines = get_lines_to_ignore(code);
        assert_eq!(lines.len(), 2);
        assert!(lines.contains(&2));
        assert!(lines.contains(&4));
    }

    #[test]
    fn test_get_lines_to_ignore_not_at_start() {
        // Directives not at the start of the line should not match
        let code = "foo # no-dd-secrets\nbar // no-dd-secrets\nbaz";
        let lines = get_lines_to_ignore(code);
        assert!(lines.is_empty());
    }

    #[test]
    fn test_get_lines_to_ignore_with_spaces_in_directive() {
        // Spaces within the directive should be removed
        let code = "#  n o - d d - s e c r e t s\n# no-dd-secrets";
        let lines = get_lines_to_ignore(code);
        assert_eq!(lines.len(), 2);
        assert!(lines.contains(&1));
        assert!(lines.contains(&2));
    }

    #[test]
    fn test_get_lines_to_ignore_mixed_patterns() {
        let code = "#no-dd-secrets\n//no-dd-secrets\n# no-dd-secrets\n// no-dd-secrets";
        let lines = get_lines_to_ignore(code);
        assert_eq!(lines.len(), 4);
        assert!(lines.contains(&1));
        assert!(lines.contains(&2));
        assert!(lines.contains(&3));
        assert!(lines.contains(&4));
    }
}
