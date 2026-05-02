//! JS-side `const NAME = [...]` array literal miner for rule pre-screens.
//!
//! Some rules' tree-sitter queries are deliberately broad (e.g.
//! `(interpreted_string_literal) @literal` matches every Go string) and rely
//! on the JavaScript visit() body to do the actual filtering against a
//! hard-coded list of strings. This module extracts those lists at startup
//! so the file-level pre-screen can skip files that don't contain any of the
//! list's literals.
//!
//! # Safety direction (under-promise)
//!
//! The rule's JavaScript may transform the array elements before checking
//! them against captured node text — most commonly a regex prefix-extraction
//! (`elem.match(/^[a-z0-9]+/i)[0]`). To stay correct for both `text.includes(elem)`
//! and `text.includes(prefix(elem))` semantics, we mine **both** the full
//! element AND its leading `[a-zA-Z0-9_]+` run, OR'd together. A file that
//! contains either form passes the screen.
//!
//! # Safety gates (per prior research + extras)
//!
//! Mining is only attempted when ALL of:
//! - The const declaration is at brace-depth 0 (top of the rule's JS file).
//! - The array name does not contain `TYPE`, `KIND`, or `NODE` (those are
//!   AST-type-name lists, never substring filters).
//! - At least one element contains a non-alphanumeric character (AST type
//!   names are all snake_case alphanumeric — if every element fits that,
//!   we're probably looking at an AST-type list, not a substring list).
//! - The TS query source contains no `[` outside strings/comments
//!   (alternation may make captures non-uniform across branches; the array
//!   filter might apply to one branch only, which we can't statically prove).
//! - Every mined literal (full or leading-run prefix) is at least 3 chars
//!   long (shorter literals are too generic to screen with).
//! - The JS body contains a reference to the array name AFTER the array
//!   declaration (so the array is actually used somewhere).
//!
//! # Output
//!
//! Returns a `Vec<String>` representing a single OR-group: the file must
//! contain at least one of these literals (substring check) for the rule to
//! possibly match. The caller is responsible for `add_global_required`-ing
//! this onto the rule's `LiteralPreScreen`.

use crate::analysis::tree_sitter::TSQuery;

/// Returns a flat OR-group of required literals mined from a top-level
/// `const NAME = [...]` array in the rule's JavaScript code, or an empty
/// vector if no safely-mineable array is found.
pub fn mine_required_literals(rule_code: &str, ts_query_source: &str) -> Vec<String> {
    // The original safety gate per prior research: "skip when the TS query
    // contains `[`" (alternation may make the JS array filter apply
    // non-uniformly across branches). We relax this when the JS body uses
    // exactly one capture name — the JS treats all branches the same way,
    // so the array filter is uniform.
    if TSQuery::source_has_alternation(ts_query_source)
        && distinct_js_capture_count(rule_code) != 1
    {
        return Vec::new();
    }
    let mut out = Vec::new();
    let bytes = rule_code.as_bytes();
    let n = bytes.len();
    let mut i = 0;
    let mut brace_depth: i32 = 0;
    let mut paren_depth: i32 = 0;
    while i < n {
        // Skip line comments `// ...` and block comments `/* ... */`.
        if i + 1 < n && bytes[i] == b'/' && bytes[i + 1] == b'/' {
            while i < n && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if i + 1 < n && bytes[i] == b'/' && bytes[i + 1] == b'*' {
            i += 2;
            while i + 1 < n && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            i = (i + 2).min(n);
            continue;
        }
        // Track string literals so internal braces / brackets don't confuse us.
        if bytes[i] == b'"' || bytes[i] == b'\'' || bytes[i] == b'`' {
            let q = bytes[i];
            i += 1;
            while i < n {
                if bytes[i] == b'\\' && i + 1 < n {
                    i += 2;
                    continue;
                }
                if bytes[i] == q {
                    i += 1;
                    break;
                }
                i += 1;
            }
            continue;
        }
        match bytes[i] {
            b'{' => {
                brace_depth += 1;
                i += 1;
                continue;
            }
            b'}' => {
                brace_depth -= 1;
                i += 1;
                continue;
            }
            b'(' => {
                paren_depth += 1;
                i += 1;
                continue;
            }
            b')' => {
                paren_depth -= 1;
                i += 1;
                continue;
            }
            _ => {}
        }
        // Only look for `const ... = [...]` declarations at top level.
        if brace_depth != 0 || paren_depth != 0 {
            i += 1;
            continue;
        }
        // Match `const ` (5 chars + ws). Also accept `let ` for completeness.
        let kw_len = if rule_code[i..].starts_with("const ") {
            6
        } else if rule_code[i..].starts_with("let ") {
            4
        } else if rule_code[i..].starts_with("var ") {
            4
        } else {
            i += 1;
            continue;
        };
        let name_start = i + kw_len;
        // Skip whitespace.
        let mut j = name_start;
        while j < n && (bytes[j] == b' ' || bytes[j] == b'\t') {
            j += 1;
        }
        let id_start = j;
        // Identifier characters.
        while j < n
            && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_' || bytes[j] == b'$')
        {
            j += 1;
        }
        let id_end = j;
        if id_end == id_start {
            i += 1;
            continue;
        }
        let name = &rule_code[id_start..id_end];
        // Skip whitespace.
        while j < n && matches!(bytes[j], b' ' | b'\t' | b'\n' | b'\r') {
            j += 1;
        }
        // Expect `=`.
        if j >= n || bytes[j] != b'=' {
            i = id_end;
            continue;
        }
        j += 1;
        while j < n && matches!(bytes[j], b' ' | b'\t' | b'\n' | b'\r') {
            j += 1;
        }
        // Expect `[`.
        if j >= n || bytes[j] != b'[' {
            i = id_end;
            continue;
        }
        // Now parse string elements until matching `]`.
        let array_open = j;
        let elements = match parse_string_array(&rule_code[array_open..]) {
            Some(e) => e,
            None => {
                i = array_open + 1;
                continue;
            }
        };
        // Apply safety gates and produce the literal list. We check whether
        // the array name is referenced in the FULL code (not just after the
        // declaration) because the JS may use the array via hoisting before
        // its `const` declaration line.
        if let Some(literals) = mine_one_array(name, &elements, rule_code) {
            out.extend(literals);
        }
        // Step past the array close.
        let close_offset = match find_matching_bracket(&rule_code[array_open..]) {
            Some(o) => o,
            None => {
                i = array_open + 1;
                continue;
            }
        };
        i = array_open + close_offset + 1;
    }
    out
}

fn mine_one_array(
    name: &str,
    elements: &[String],
    full_code: &str,
) -> Option<Vec<String>> {
    // Gate: name doesn't suggest an AST-type list.
    let upper = name.to_ascii_uppercase();
    if upper.contains("TYPE") || upper.contains("KIND") || upper.contains("NODE") {
        return None;
    }
    if elements.is_empty() {
        return None;
    }
    // Gate: at least one element has a non-alphanumeric character (rules out
    // arrays of bare snake_case AST type names).
    let any_non_alnum = elements
        .iter()
        .any(|e| e.chars().any(|c| !(c.is_ascii_alphanumeric() || c == '_')));
    if !any_non_alnum {
        return None;
    }
    // Gate: the array name must be referenced somewhere else in the rule's JS
    // (could be before OR after the `const` line, since JS allows access-by-
    // hoisting from a function declared earlier). We approximate this by
    // counting occurrences of the name as a substring; if it appears more
    // than once, something else mentions it.
    if full_code.matches(name).count() <= 1 {
        return None;
    }
    // For each element, mine: the FULL element (covers `text.includes(elem)`)
    // AND the leading [a-zA-Z0-9_]+ run (covers `text.includes(elem.match(/^[a-z0-9]+/i)[0])`).
    let mut out: Vec<String> = Vec::with_capacity(elements.len() * 2);
    for elem in elements {
        if elem.len() >= 3 {
            out.push(elem.clone());
        }
        let prefix = leading_alnum_run(elem);
        if prefix.len() >= 3 && prefix != *elem {
            out.push(prefix);
        }
    }
    if out.is_empty() {
        return None;
    }
    // Dedup (cheap; lists are small).
    out.sort_unstable();
    out.dedup();
    Some(out)
}

/// Take the leading run of `[a-zA-Z0-9_]` characters.
fn leading_alnum_run(s: &str) -> String {
    s.chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect()
}

/// Count distinct capture names referenced in the JS body via
/// `query.captures.X`, `query.captures["X"]`, `query.capturesList.X`, or
/// `query.capturesList["X"]`. We're heuristic, not a JS parser; this is
/// deliberately approximate but sufficient for the safety check.
fn distinct_js_capture_count(js: &str) -> usize {
    let bytes = js.as_bytes();
    let n = bytes.len();
    let mut seen = std::collections::HashSet::<&str>::new();
    let mut i = 0;
    let needles: [&[u8]; 4] = [
        b"query.captures.",
        b"query.captures[",
        b"query.capturesList.",
        b"query.capturesList[",
    ];
    while i < n {
        let mut matched = false;
        for needle in &needles {
            if i + needle.len() <= n && &bytes[i..i + needle.len()] == *needle {
                let after = i + needle.len();
                let (name_start, name_end) = if needle.ends_with(b"[") {
                    // bracket form: skip optional quote, then take identifier-ish chars
                    let mut j = after;
                    if j < n && (bytes[j] == b'"' || bytes[j] == b'\'' || bytes[j] == b'`') {
                        j += 1;
                    }
                    let s = j;
                    while j < n
                        && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_' || bytes[j] == b'-' || bytes[j] == b'$')
                    {
                        j += 1;
                    }
                    (s, j)
                } else {
                    // dot form: identifier chars after the dot
                    let mut j = after;
                    while j < n
                        && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_' || bytes[j] == b'$')
                    {
                        j += 1;
                    }
                    (after, j)
                };
                if name_end > name_start {
                    if let Ok(name) = std::str::from_utf8(&bytes[name_start..name_end]) {
                        seen.insert(name);
                    }
                }
                i = name_end;
                matched = true;
                break;
            }
        }
        if !matched {
            i += 1;
        }
    }
    seen.len()
}

/// Parse a JS array literal of strings. Returns the parsed elements (with
/// escape decoding) or `None` if the input isn't a clean string array.
fn parse_string_array(src: &str) -> Option<Vec<String>> {
    let bytes = src.as_bytes();
    if bytes.is_empty() || bytes[0] != b'[' {
        return None;
    }
    let mut elements = Vec::new();
    let mut i = 1;
    let n = bytes.len();
    while i < n {
        // Skip whitespace and commas.
        while i < n && matches!(bytes[i], b' ' | b'\t' | b'\n' | b'\r' | b',') {
            i += 1;
        }
        if i >= n {
            return None;
        }
        if bytes[i] == b']' {
            return Some(elements);
        }
        // Skip line comments and block comments inside the array.
        if i + 1 < n && bytes[i] == b'/' && bytes[i + 1] == b'/' {
            while i < n && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if i + 1 < n && bytes[i] == b'/' && bytes[i + 1] == b'*' {
            i += 2;
            while i + 1 < n && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            i = (i + 2).min(n);
            continue;
        }
        // Expect a string literal: ' " or `.
        if !matches!(bytes[i], b'\'' | b'"' | b'`') {
            // Anything else (numbers, identifiers, nested arrays, objects) →
            // bail; this isn't a clean string array.
            return None;
        }
        let q = bytes[i];
        i += 1;
        let mut out = Vec::new();
        while i < n {
            if bytes[i] == b'\\' && i + 1 < n {
                let e = bytes[i + 1];
                out.push(match e {
                    b'n' => b'\n',
                    b't' => b'\t',
                    b'r' => b'\r',
                    b'\\' => b'\\',
                    other => other,
                });
                i += 2;
                continue;
            }
            if bytes[i] == q {
                i += 1;
                break;
            }
            out.push(bytes[i]);
            i += 1;
        }
        let s = match String::from_utf8(out) {
            Ok(s) => s,
            Err(_) => return None,
        };
        elements.push(s);
    }
    None
}

fn find_matching_bracket(src: &str) -> Option<usize> {
    let bytes = src.as_bytes();
    if bytes.is_empty() || bytes[0] != b'[' {
        return None;
    }
    let mut depth: i32 = 0;
    let mut i = 0;
    let n = bytes.len();
    while i < n {
        match bytes[i] {
            b'\'' | b'"' | b'`' => {
                let q = bytes[i];
                i += 1;
                while i < n {
                    if bytes[i] == b'\\' && i + 1 < n {
                        i += 2;
                        continue;
                    }
                    if bytes[i] == q {
                        i += 1;
                        break;
                    }
                    i += 1;
                }
            }
            b'[' => {
                depth += 1;
                i += 1;
            }
            b']' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
                i += 1;
            }
            _ => i += 1,
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mines_full_and_prefix_for_dotted_strings() {
        let js = r#"
            const clusters = ['annihilape.ap1.prod.dog', 'blastoise.ap1.prod.dog'];
            function visit() { clusters.reduce(...) }
        "#;
        let ts = "(interpreted_string_literal) @literal";
        let lits = mine_required_literals(js, ts);
        // Should include both full names AND leading-run prefixes.
        assert!(lits.iter().any(|l| l == "annihilape.ap1.prod.dog"));
        assert!(lits.iter().any(|l| l == "annihilape"));
        assert!(lits.iter().any(|l| l == "blastoise.ap1.prod.dog"));
        assert!(lits.iter().any(|l| l == "blastoise"));
    }

    #[test]
    fn skips_array_with_type_in_name() {
        let js = "const NODE_TYPES = ['identifier', 'method_call'];\nfunction visit() { NODE_TYPES.includes(...) }";
        let ts = "(_)";
        assert!(mine_required_literals(js, ts).is_empty());
    }

    #[test]
    fn skips_array_with_kind_in_name() {
        let js = "const SUSPICIOUS_KIND = ['eval', 'exec'];\nfunction visit() { SUSPICIOUS_KIND.includes(...) }";
        assert!(mine_required_literals(js, "(_)").is_empty());
    }

    #[test]
    fn skips_array_with_node_in_name() {
        let js = "const ALL_NODE = ['call_expression', 'identifier'];\nfunction visit() { ALL_NODE.includes(...) }";
        assert!(mine_required_literals(js, "(_)").is_empty());
    }

    #[test]
    fn skips_alphanumeric_only_arrays() {
        // Looks like AST type names — bail.
        let js = "const SHAPES = ['circle', 'square', 'triangle'];\nfunction visit() { SHAPES.includes(...) }";
        assert!(mine_required_literals(js, "(_)").is_empty());
    }

    #[test]
    fn skips_when_ts_query_has_alternation_and_multiple_js_captures() {
        // TS alternation + JS uses both `query.captures.a` and
        // `query.captures.b` → unsafe to mine; bail.
        let js = r#"const URLS = ['foo.bar.com', 'baz.qux.org'];
function visit(query) {
    if (query.captures.a) { URLS.includes(query.captures.a.text); }
    if (query.captures.b) { URLS.includes(query.captures.b.text); }
}"#;
        let ts = "[(_) @a (_) @b]";
        assert!(mine_required_literals(js, ts).is_empty());
    }

    #[test]
    fn allows_alternation_when_js_uses_single_capture() {
        // TS alternation but JS only references `query.captures.literal`,
        // i.e. uniform handling across branches → mining is safe.
        let js = r#"const URLS = ['foo.bar.com', 'baz.qux.org'];
function visit(query) {
    const node = query.captures.literal;
    URLS.find(u => node.text.includes(u));
}"#;
        let ts = "[(a) (b) (c)] @literal";
        let lits = mine_required_literals(js, ts);
        assert!(!lits.is_empty());
        assert!(lits.iter().any(|l| l == "foo.bar.com"));
    }

    #[test]
    fn skips_inside_function_body() {
        // const declaration is inside a function — not top-level. Bail.
        let js = "function visit() { const URLS = ['foo.bar.com', 'baz.qux.org']; URLS.includes(...) }";
        assert!(mine_required_literals(js, "(_)").is_empty());
    }

    #[test]
    fn skips_array_not_referenced_later() {
        // Declared but never used → not a substring filter, skip.
        // (The reference check looks at the post-declaration code only.)
        let js = "const ABCDEF = ['foo.bar.com'];\nfunction visit() {}";
        assert!(mine_required_literals(js, "(_)").is_empty());
    }

    #[test]
    fn handles_let_and_var() {
        let js = "let MY_DCS = ['foo.bar.com', 'baz.qux.com'];\nfunction visit() { MY_DCS.find(...) }";
        let lits = mine_required_literals(js, "(_)");
        assert!(lits.iter().any(|l| l == "foo.bar.com"));
        assert!(lits.iter().any(|l| l == "foo"));
    }

    #[test]
    fn skips_short_prefixes() {
        // Prefix "x" too short.
        let js = "const URLS = ['x.foo', 'y.bar'];\nfunction visit() { URLS.find(...) }";
        let lits = mine_required_literals(js, "(_)");
        // We still mine the full "x.foo" if >=3 chars; "y.bar" same.
        // But the "x" / "y" prefixes are too short and skipped.
        assert!(lits.contains(&"x.foo".to_string()));
        assert!(lits.contains(&"y.bar".to_string()));
        assert!(!lits.contains(&"x".to_string()));
        assert!(!lits.contains(&"y".to_string()));
    }

    #[test]
    fn handles_dashes_in_names() {
        // brionne-a -> leading [a-zA-Z0-9_]+ run = "brionne" (stops at '-').
        let js = "const clusters = ['brionne-a.ap1.prod.dog'];\nfunction visit() { clusters.find(...) }";
        let lits = mine_required_literals(js, "(_)");
        assert!(lits.iter().any(|l| l == "brionne-a.ap1.prod.dog"));
        assert!(lits.iter().any(|l| l == "brionne"));
    }
}
