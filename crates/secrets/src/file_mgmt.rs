// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026 Datadog, Inc.

use std::collections::HashSet;

/// Get the line numbers to ignore based on `no-dd-secrets` directives.
/// Returns the line numbers AFTER each directive (the lines that should be ignored).
/// Only lines starting with `#no-dd-secrets` or `//no-dd-secrets` (after stripping tabs and spaces) are matched.
pub fn get_lines_to_ignore(code: &str) -> HashSet<u32> {
    const DISABLE_PATTERNS: [&str; 2] = ["#no-dd-secrets", "//no-dd-secrets"];

    let mut lines_to_ignore = HashSet::new();

    for (idx, line) in code.lines().enumerate() {
        let line_number = (idx + 1) as u32;

        // Strip all tabs and spaces from the line
        let stripped_line: String = line.chars().filter(|c| !c.is_whitespace()).collect();

        // Check if the stripped line starts with any of the disable patterns
        for pattern in &DISABLE_PATTERNS {
            if stripped_line.starts_with(pattern) {
                // Directive applies to the NEXT line
                lines_to_ignore.insert(line_number + 1);
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
        // Directive on line 2 should ignore line 3
        let code = "foo\n# no-dd-secrets\nbar";
        let lines = get_lines_to_ignore(code);
        assert_eq!(lines.len(), 1);
        assert!(lines.contains(&3)); // Line 3 (bar) should be ignored
    }

    #[test]
    fn test_get_lines_to_ignore_multiple_lines() {
        // Directive on line 2 should ignore line 3, directive on line 4 should ignore line 5
        let code = "foo\n# no-dd-secrets\nbar\n// no-dd-secrets\nbaz";
        let lines = get_lines_to_ignore(code);
        assert_eq!(lines.len(), 2);
        assert!(lines.contains(&3)); // Line 3 (bar) should be ignored
        assert!(lines.contains(&5)); // Line 5 (baz) should be ignored
    }

    #[test]
    fn test_get_lines_to_ignore_with_tabs_and_spaces() {
        // Directive on line 2 should ignore line 3, directive on line 4 should ignore line 5
        let code = "foo\n\t  # no-dd-secrets\nbar\n  \t// no-dd-secrets\nbaz";
        let lines = get_lines_to_ignore(code);
        assert_eq!(lines.len(), 2);
        assert!(lines.contains(&3)); // Line 3 (bar) should be ignored
        assert!(lines.contains(&5)); // Line 5 (baz) should be ignored
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
        let code = "#  n o - d d - s e c r e t s\n# no-dd-secrets\nfoo";
        let lines = get_lines_to_ignore(code);
        assert_eq!(lines.len(), 2);
        assert!(lines.contains(&2));
        assert!(lines.contains(&3));

        let code2 = "foo\n#  n o - d d - s e c r e t s\nbar";
        let lines2 = get_lines_to_ignore(code2);
        assert_eq!(lines2.len(), 1);
        assert!(lines2.contains(&3)); // Line after directive on line 2
    }

    #[test]
    fn test_get_lines_to_ignore_mixed_patterns_not_first_line() {
        // All directives not on first line
        let code = "foo\n//no-dd-secrets\nbar\n# no-dd-secrets\nbaz\n// no-dd-secrets";
        let lines = get_lines_to_ignore(code);
        assert_eq!(lines.len(), 3);
        assert!(lines.contains(&3)); // Line after //no-dd-secrets on line 2
        assert!(lines.contains(&5)); // Line after # no-dd-secrets on line 4
        assert!(lines.contains(&7)); // Line after // no-dd-secrets on line 6
    }
}
