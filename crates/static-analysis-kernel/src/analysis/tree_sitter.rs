use crate::model::analysis::{MatchNode, MatchNodeContext, TreeSitterNode};
use crate::model::common::Language;
use common::model::position::Position;
use indexmap::IndexMap;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use streaming_iterator::StreamingIterator;
use tree_sitter::CaptureQuantifier;

pub fn get_tree_sitter_language(language: &Language) -> tree_sitter::Language {
    extern "C" {
        fn tree_sitter_c_sharp() -> tree_sitter::Language;
        fn tree_sitter_dart() -> tree_sitter::Language;
        fn tree_sitter_dockerfile() -> tree_sitter::Language;
        fn tree_sitter_elixir() -> tree_sitter::Language;
        fn tree_sitter_go() -> tree_sitter::Language;
        fn tree_sitter_java() -> tree_sitter::Language;
        fn tree_sitter_javascript() -> tree_sitter::Language;
        fn tree_sitter_json() -> tree_sitter::Language;
        fn tree_sitter_kotlin() -> tree_sitter::Language;
        fn tree_sitter_python() -> tree_sitter::Language;
        fn tree_sitter_ruby() -> tree_sitter::Language;
        fn tree_sitter_rust() -> tree_sitter::Language;
        fn tree_sitter_swift() -> tree_sitter::Language;
        fn tree_sitter_tsx() -> tree_sitter::Language;
        fn tree_sitter_hcl() -> tree_sitter::Language;
        fn tree_sitter_yaml() -> tree_sitter::Language;
        fn tree_sitter_starlark() -> tree_sitter::Language;
        fn tree_sitter_bash() -> tree_sitter::Language;
        fn tree_sitter_php() -> tree_sitter::Language;
        fn tree_sitter_markdown() -> tree_sitter::Language;
        fn tree_sitter_apex() -> tree_sitter::Language;
        fn tree_sitter_r() -> tree_sitter::Language;
        fn tree_sitter_sql() -> tree_sitter::Language;
    }

    match language {
        Language::Csharp => unsafe { tree_sitter_c_sharp() },
        Language::Dart => unsafe { tree_sitter_dart() },
        Language::Dockerfile => unsafe { tree_sitter_dockerfile() },
        Language::Go => unsafe { tree_sitter_go() },
        Language::Elixir => unsafe { tree_sitter_elixir() },
        Language::Java => unsafe { tree_sitter_java() },
        Language::JavaScript => unsafe { tree_sitter_javascript() },
        Language::Kotlin => unsafe { tree_sitter_kotlin() },
        Language::Json => unsafe { tree_sitter_json() },
        Language::Python => unsafe { tree_sitter_python() },
        Language::Ruby => unsafe { tree_sitter_ruby() },
        Language::Rust => unsafe { tree_sitter_rust() },
        Language::Swift => unsafe { tree_sitter_swift() },
        Language::Terraform => unsafe { tree_sitter_hcl() },
        Language::TypeScript => unsafe { tree_sitter_tsx() },
        Language::Yaml => unsafe { tree_sitter_yaml() },
        Language::Starlark => unsafe { tree_sitter_starlark() },
        Language::Bash => unsafe { tree_sitter_bash() },
        Language::PHP => unsafe { tree_sitter_php() },
        Language::Markdown => unsafe { tree_sitter_markdown() },
        Language::Apex => unsafe { tree_sitter_apex() },
        Language::R => unsafe { tree_sitter_r() },
        Language::SQL => unsafe { tree_sitter_sql() },
    }
}

// get the tree-sitter tree
pub fn get_tree(code: &str, language: &Language) -> Option<tree_sitter::Tree> {
    let mut tree_sitter_parser = tree_sitter::Parser::new();
    let tree_sitter_language = get_tree_sitter_language(language);
    tree_sitter_parser
        .set_language(&tree_sitter_language)
        .ok()?;
    tree_sitter_parser.parse(code, None)
}

// build the query from tree-sitter
pub fn get_query(
    query_code: &str,
    language: &Language,
) -> Result<TSQuery, tree_sitter::QueryError> {
    let tree_sitter_language = get_tree_sitter_language(language);
    TSQuery::try_new(&tree_sitter_language, query_code)
}

/// A wrapper around a [`tree_sitter::Query`].
#[derive(Debug)]
pub struct TSQuery {
    query: tree_sitter::Query,
    capture_names: Vec<Arc<str>>,
    /// A conservative literal pre-screen extracted from the query source.
    /// If non-empty, a file's source code must contain at least one literal
    /// from each AND-group for the rule to *possibly* match. Files that fail
    /// the screen can skip the v8 dispatch (and, at the file level, the
    /// tree-sitter parse) without changing semantics.
    pre_screen: LiteralPreScreen,
}

impl TSQuery {
    pub fn try_new(
        language: &tree_sitter::Language,
        source: &str,
    ) -> Result<Self, tree_sitter::QueryError> {
        let query = tree_sitter::Query::new(language, source)?;
        let capture_names = Self::build_cache(&query);
        let pre_screen = LiteralPreScreen::extract_from_query(&query, source);
        Ok(Self {
            query,
            capture_names,
            pre_screen,
        })
    }

    /// Returns the literal pre-screen for this query (cheap to call, no allocations).
    #[inline]
    pub fn pre_screen(&self) -> &LiteralPreScreen {
        &self.pre_screen
    }

    /// Returns a [`TSQueryCursor`] bound to the provided cursor.
    pub fn with_cursor<'a, 'tree: 'a>(
        &'a self,
        cursor: &'a mut tree_sitter::QueryCursor,
    ) -> TSQueryCursor<'a, 'tree> {
        TSQueryCursor {
            query: &self.query,
            capture_names: self.capture_names.as_slice(),
            cursor: MaybeOwnedMut::Borrowed(cursor),
            captures_scratch: IndexMap::new(),
        }
    }

    /// A convenience function to return a [`TSQueryCursor`].
    ///
    /// This is relatively slow, as it allocates a new [`tree_sitter::QueryCursor`] and drops it after
    /// performing the query. Consider using [`TSQuery::with_cursor`] where possible.
    pub fn cursor(&self) -> TSQueryCursor<'_, '_> {
        let cursor = MaybeOwnedMut::Owned(tree_sitter::QueryCursor::new());
        TSQueryCursor {
            query: &self.query,
            capture_names: self.capture_names.as_slice(),
            cursor,
            captures_scratch: IndexMap::new(),
        }
    }

    /// Generates a cache of the capture names as an [`Arc<str>`].
    fn build_cache(query: &tree_sitter::Query) -> Vec<Arc<str>> {
        query
            .capture_names()
            .iter()
            .map(|&name| Arc::from(name))
            .collect::<Vec<_>>()
    }
}

impl From<tree_sitter::Query> for TSQuery {
    fn from(value: tree_sitter::Query) -> Self {
        let capture_names = TSQuery::build_cache(&value);
        Self {
            query: value,
            capture_names,
            // We only have the compiled query here, no source string to scan,
            // so there's no usable pre-screen.
            pre_screen: LiteralPreScreen::always_match(),
        }
    }
}

/// A conservative literal pre-screen extracted from a tree-sitter query source.
///
/// A query may have multiple top-level patterns OR'd together (`pattern_count
/// > 1`). For the rule to match a file, ANY of those patterns must match —
/// so the pre-screen is `OR over patterns(AND over groups(OR over literals))`.
///
/// Built once per query (at startup). Used per-file in the analyzer hot path,
/// so `matches()` is allocation-free and uses `str::contains` (memchr/SIMD).
///
/// **Safety direction:** under-promise. Adding too few groups misses
/// optimization but never blocks a file that should match. Adding too many is
/// a correctness bug. We therefore only extract literals when we can prove
/// they're required for that pattern to match:
///
/// - We extract from `(#eq? @cap "lit")` (single literal, single AND-group).
/// - We extract from `(#any-of? @cap "lit1" "lit2")` (one OR-group).
/// - We extract the longest contiguous literal run from `#match?` regexes
///   (with safety bails on `|`, `(?...)` modifiers, runs <3 chars).
/// - We bail per-pattern on any `[` (alternation) outside strings/comments.
/// - We bail the WHOLE screen (every pattern is required) if any pattern
///   ends up with zero AND-groups — an unconstrained pattern can match
///   anything, so the file cannot be safely skipped.
#[derive(Debug, Default, Clone)]
pub struct LiteralPreScreen {
    /// OR over patterns. For each pattern, ALL of its OR-groups must contain
    /// at least one literal that's in the file. An empty outer Vec means
    /// no screen possible (every file must run the rule).
    patterns: Vec<Vec<Vec<String>>>,
}

impl LiteralPreScreen {
    /// A pre-screen that lets every file through.
    pub fn always_match() -> Self {
        Self {
            patterns: Vec::new(),
        }
    }

    /// Returns `true` if this pre-screen has no groups (i.e. `matches()` is a no-op).
    #[inline]
    pub fn is_trivial(&self) -> bool {
        self.patterns.is_empty()
    }

    /// Returns `true` if `code` *could* satisfy at least one of the query's
    /// patterns, or if no pre-screen is available (in which case the caller
    /// must run the full query). Allocation-free.
    #[inline]
    pub fn matches(&self, code: &str) -> bool {
        self.patterns.is_empty()
            || self.patterns.iter().any(|and_groups| {
                and_groups
                    .iter()
                    .all(|or_group| or_group.iter().any(|lit| code.contains(lit.as_str())))
            })
    }

    /// Build a pre-screen from a compiled query and its source string by
    /// iterating each top-level pattern's source-slice via
    /// [`tree_sitter::Query::start_byte_for_pattern`]. Per-pattern,
    /// `extract_and_groups_from_pattern_source` only extracts predicates at
    /// `[`-depth 0 and not inside any `?`/`*`/`+`-quantified group, so it's
    /// safe to call even on patterns that themselves contain `[...]`
    /// elsewhere.
    pub fn extract_from_query(query: &tree_sitter::Query, source: &str) -> Self {
        let pcount = query.pattern_count();
        if pcount == 0 {
            return Self::always_match();
        }

        let bytes = source.as_bytes();
        let mut patterns: Vec<Vec<Vec<String>>> = Vec::with_capacity(pcount);
        for p in 0..pcount {
            let start = query.start_byte_for_pattern(p);
            let end = query.end_byte_for_pattern(p);
            // Defensive: guard against ranges that don't fit (shouldn't happen).
            if start >= bytes.len() || end > bytes.len() || start >= end {
                return Self::always_match();
            }
            let slice = &source[start..end];
            let and_groups = extract_and_groups_from_pattern_source(slice);
            if and_groups.is_empty() {
                // Unconstrained pattern: it can match arbitrary code, so the
                // rule (`OR of patterns`) can match arbitrary code too. We
                // can't safely skip files based on the other patterns alone.
                return Self::always_match();
            }
            patterns.push(and_groups);
        }
        Self { patterns }
    }

    /// Single-pattern shorthand used by tests. Behaves like `extract_from_query`
    /// but takes the source directly when we don't already have a compiled query.
    #[cfg(test)]
    pub fn extract(source: &str, pattern_count: usize) -> Self {
        if pattern_count != 1 {
            return Self::always_match();
        }
        let and_groups = extract_and_groups_from_pattern_source(source);
        if and_groups.is_empty() {
            return Self::always_match();
        }
        Self {
            patterns: vec![and_groups],
        }
    }
}

/// Walk a (single-pattern) query source and collect `#eq?` / `#any-of?` /
/// `#match?` literals as AND-groups.
///
/// **Conservatism gate:** we only extract a predicate when it is
/// unconditionally required — i.e. when its enclosing groups are not
/// behind an `[...]` alternation or a `?` / `*` / `+` quantifier. If any
/// suffix-quantifier or alternation appears anywhere in the pattern, we
/// take the safe path and skip extraction for predicates that *might* sit
/// inside the conditional region.
///
/// Implementation:
/// - Track `[` depth. Only depth-0 predicates are eligible (alternation
///   wraps multiple branches, predicates inside one branch aren't required).
/// - Track an "in conditional" stack: for each open paren, record whether
///   it'll later be quantified by `?`, `*`, or `+`. We can't know this
///   until we see the close — so we collect predicate candidates with their
///   span and apply the filter at close time.
///
/// To keep this single-pass and simple, we collect candidates as
/// `(predicate_kind, predicate_byte_range)` and then post-filter. The
/// filter checks every enclosing `)` quantifier suffix in the source.
fn extract_and_groups_from_pattern_source(source: &str) -> Vec<Vec<String>> {
    let bytes = source.as_bytes();
    let n = bytes.len();

    // Pass 1: walk the source, building an open-paren stack with the byte
    // position of each `(`. For each `)`, peek at the following non-comment
    // byte; if it's `?`, `*`, or `+`, record that span as "conditional".
    // Collect predicate spans as we go.
    #[derive(Debug)]
    struct Predicate {
        // Source offsets of the `(` and `)` that wrap the predicate.
        open: usize,
        close: usize,
        // Stack of enclosing `(...)` opens at the moment we entered the predicate.
        enclosing_opens: Vec<usize>,
        // True if the predicate is at `[`-depth 0.
        bracket_depth_zero: bool,
    }
    let mut predicates: Vec<Predicate> = Vec::new();
    let mut paren_stack: Vec<usize> = Vec::new();
    // `conditional_opens`: set of `(` byte-positions whose closing paren is
    // followed by a `?`, `*`, or `+` quantifier (or which sit inside `[...]`
    // alternation — same effect: the contents aren't unconditionally required).
    let mut conditional_opens: std::collections::HashSet<usize> = std::collections::HashSet::new();
    let mut bracket_depth: i32 = 0;
    // Stack of `[`-open positions, for tracking which `(` opens were entered
    // while inside an alternation. The last-popped `[` doesn't matter for
    // correctness because we already use bracket_depth.
    let mut i = 0;
    while i < n {
        match bytes[i] {
            b';' => {
                while i < n && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'"' => {
                i += 1;
                while i < n {
                    if bytes[i] == b'\\' && i + 1 < n {
                        i += 2;
                        continue;
                    }
                    if bytes[i] == b'"' {
                        i += 1;
                        break;
                    }
                    i += 1;
                }
            }
            b'[' => {
                bracket_depth += 1;
                i += 1;
            }
            b']' => {
                if bracket_depth > 0 {
                    bracket_depth -= 1;
                }
                i += 1;
            }
            b'(' => {
                let mut j = i + 1;
                while j < n && matches!(bytes[j], b' ' | b'\t' | b'\n' | b'\r') {
                    j += 1;
                }
                let is_predicate = j < n && bytes[j] == b'#';
                paren_stack.push(i);
                if is_predicate {
                    if let Some(close) = find_matching_paren(bytes, i) {
                        let enclosing_opens = paren_stack[..paren_stack.len() - 1].to_vec();
                        predicates.push(Predicate {
                            open: i,
                            close,
                            enclosing_opens,
                            bracket_depth_zero: bracket_depth == 0,
                        });
                        // Pop the predicate's own open from the stack — it'll
                        // be re-added when the outer scan reaches `close`.
                        // (We skip past it directly.)
                        paren_stack.pop();
                        i = close + 1;
                        continue;
                    }
                }
                i += 1;
            }
            b')' => {
                let opened = paren_stack.pop();
                // Look ahead past whitespace/comments for a quantifier suffix.
                let mut j = i + 1;
                while j < n && matches!(bytes[j], b' ' | b'\t' | b'\n' | b'\r') {
                    j += 1;
                }
                let quantified = j < n && matches!(bytes[j], b'?' | b'*' | b'+');
                if quantified {
                    if let Some(open_pos) = opened {
                        conditional_opens.insert(open_pos);
                    }
                }
                // Also: any `(` opened while inside `[...]` alternation
                // is conditional, since the enclosing alternation makes
                // even unquantified groups optional in spirit. We mark
                // that at `(` time by checking bracket_depth.
                i += 1;
            }
            _ => i += 1,
        }
    }

    // Pass 2: filter predicates. Keep a predicate only if:
    // - it's at bracket-depth 0, AND
    // - none of its enclosing opens is conditional.
    let mut and_groups: Vec<Vec<String>> = Vec::new();
    for p in &predicates {
        if !p.bracket_depth_zero {
            continue;
        }
        if p.enclosing_opens
            .iter()
            .any(|o| conditional_opens.contains(o))
        {
            continue;
        }
        let inner = &source[p.open + 1..p.close];
        if let Some(group) = parse_text_predicate_literals(inner) {
            and_groups.push(group);
        }
    }
    and_groups
}

// (Earlier versions had `has_alternation_bracket` as a coarse pre-bail; the
// current `extract_and_groups_from_pattern_source` tracks bracket depth and
// quantifier suffixes precisely, so a top-level utility is no longer needed.)

/// Find the index of the matching `)` for the `(` at `open`, respecting
/// strings and line comments. Returns `None` if the source is malformed.
fn find_matching_paren(bytes: &[u8], open: usize) -> Option<usize> {
    debug_assert_eq!(bytes[open], b'(');
    let mut depth: i32 = 0;
    let mut i = open;
    let n = bytes.len();
    while i < n {
        match bytes[i] {
            b';' => {
                while i < n && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'"' => {
                i += 1;
                while i < n {
                    if bytes[i] == b'\\' && i + 1 < n {
                        i += 2;
                        continue;
                    }
                    if bytes[i] == b'"' {
                        i += 1;
                        break;
                    }
                    i += 1;
                }
            }
            b'(' => {
                depth += 1;
                i += 1;
            }
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
                i += 1;
            }
            _ => {
                i += 1;
            }
        }
    }
    None
}

/// Parse the body of a text-predicate s-expression (the bytes between the
/// outermost `(` and `)`, exclusive) and return the OR-group of literals it
/// requires, if it's a `#eq?` or `#any-of?` predicate. Other predicates and
/// any unexpected shape return `None` (don't constrain the screen).
fn parse_text_predicate_literals(inner: &str) -> Option<Vec<String>> {
    let mut tokens = TextPredicateTokens::new(inner);
    let kind = tokens.next_word()?;
    // Capture-form `#eq?` requires `@cap1 @cap2` (capture-vs-capture) which
    // can't be reduced to a literal screen, so we only proceed if the FIRST
    // arg is `@cap` and the SECOND is a string literal.
    let first_arg = tokens.next_arg()?;
    if !first_arg.starts_with('@') {
        return None;
    }
    match kind {
        "#eq?" | "#not-eq?" | "#any-eq?" | "#any-not-eq?" => {
            // Negative forms (#not-eq?, #any-not-eq?) cannot be used to require
            // a literal's presence — they require its absence. Skip them.
            if kind != "#eq?" && kind != "#any-eq?" {
                return None;
            }
            let lit = tokens.next_string_literal()?;
            // Sanity: skip empty / whitespace-only literals.
            if lit.trim().is_empty() {
                return None;
            }
            Some(vec![lit])
        }
        "#any-of?" => {
            let mut group = Vec::new();
            while let Some(lit) = tokens.next_string_literal() {
                if !lit.trim().is_empty() {
                    group.push(lit);
                }
            }
            // If we ended up with no literals (or any was ill-formed), give up.
            if group.is_empty() {
                None
            } else {
                Some(group)
            }
        }
        "#match?" => {
            // Extract the longest contiguous literal run from the regex source.
            // Safe IFF the regex has no top-level `|` alternation and no
            // `(?...)` group modifiers (notably `(?i)` case-insensitive).
            let regex_src = tokens.next_string_literal()?;
            let lit = extract_required_literal_from_regex(&regex_src)?;
            if lit.trim().is_empty() {
                return None;
            }
            Some(vec![lit])
        }
        // `#not-match?`, `#is?`, custom predicates: not extracted.
        _ => None,
    }
}

/// Extract the longest contiguous run of literal characters from a regex,
/// to be used as a required-literal screening hint. Returns `None` when the
/// regex is too unconstrained for safe extraction.
///
/// Safety:
/// - Bails on top-level `|` alternation (different branches → different literals).
/// - Bails on `(?...)` group-modifier prefixes (e.g. `(?i)` case-insensitive
///   would make the extracted literal wrong-case).
/// - Treats `^`, `$`, anchors, zero-width assertions, and unescaped
///   `.`, `*`, `+`, `?`, `{`, `[`, `(` as run boundaries.
/// - Decodes `\X` for `X` in the standard regex special set as a literal `X`.
///   Other escapes (`\n`, `\t`, `\d`, `\w`, etc.) end the current run.
///
/// Returns the longest run found, e.g.:
/// - `"gopkg.in/DataDog/dd-trace-go.v1/.*"` → `"in/DataDog/dd-trace-go"`
/// - `r"^\".*\.fabric\.dog.*\"$"` → `".fabric.dog"`
fn extract_required_literal_from_regex(re: &str) -> Option<String> {
    let bytes = re.as_bytes();
    let n = bytes.len();

    // Quick global bails. Top-level `|` would split into alternatives with
    // different requirements; we'd need per-branch handling.
    if has_unescaped(bytes, b'|') {
        return None;
    }
    if has_group_modifier(bytes) {
        return None;
    }

    let mut runs: Vec<Vec<u8>> = Vec::new();
    let mut current: Vec<u8> = Vec::new();
    let mut i = 0;
    while i < n {
        let c = bytes[i];
        if c == b'\\' && i + 1 < n {
            let next = bytes[i + 1];
            // Treat `\X` as a literal `X` only for the regex meta-set.
            // Other escapes (`\d`, `\w`, `\s`, `\b`, hex escapes, etc.) end
            // the run — those don't pin a single character.
            const META: &[u8] = b".*+?{}|()[]^$\\/";
            if META.contains(&next) {
                current.push(next);
                i += 2;
                continue;
            } else {
                runs.push(std::mem::take(&mut current));
                i += 2;
                continue;
            }
        }
        // Run-ending metachars (we already excluded `|`).
        if matches!(
            c,
            b'.' | b'*' | b'+' | b'?' | b'{' | b'[' | b'(' | b'^' | b'$' | b')' | b'}' | b']'
        ) {
            runs.push(std::mem::take(&mut current));
            i += 1;
            continue;
        }
        // Non-printable / non-ASCII: end the run conservatively.
        if !c.is_ascii_graphic() && c != b' ' {
            runs.push(std::mem::take(&mut current));
            i += 1;
            continue;
        }
        current.push(c);
        i += 1;
    }
    runs.push(current);

    let longest = runs.into_iter().max_by_key(|r| r.len())?;
    if longest.len() < 3 {
        // Runs shorter than 3 chars are too generic to screen safely (they'd
        // appear in nearly every file).
        return None;
    }
    String::from_utf8(longest).ok()
}

fn has_unescaped(bytes: &[u8], target: u8) -> bool {
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            i += 2;
            continue;
        }
        if bytes[i] == target {
            return true;
        }
        i += 1;
    }
    false
}

fn has_group_modifier(bytes: &[u8]) -> bool {
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            i += 2;
            continue;
        }
        if bytes[i] == b'(' && bytes[i + 1] == b'?' {
            return true;
        }
        i += 1;
    }
    false
}

/// Minimal lexer over a tree-sitter predicate body. Skips whitespace, parses
/// `@captures`, words like `#eq?`, and double-quoted string literals (with
/// `\\` and `\"` escapes). Anything else is treated as a generic word.
struct TextPredicateTokens<'a> {
    s: &'a [u8],
    i: usize,
}

impl<'a> TextPredicateTokens<'a> {
    fn new(s: &'a str) -> Self {
        Self {
            s: s.as_bytes(),
            i: 0,
        }
    }

    fn skip_ws(&mut self) {
        while self.i < self.s.len() && matches!(self.s[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }

    /// Returns the next non-whitespace word (ending at whitespace or `)`).
    fn next_word(&mut self) -> Option<&'a str> {
        self.skip_ws();
        if self.i >= self.s.len() || self.s[self.i] == b'"' {
            return None;
        }
        let start = self.i;
        while self.i < self.s.len()
            && !matches!(self.s[self.i], b' ' | b'\t' | b'\n' | b'\r' | b')')
        {
            self.i += 1;
        }
        if start == self.i {
            return None;
        }
        // Safe: we only stepped over ASCII whitespace boundaries; the slice is valid UTF-8.
        std::str::from_utf8(&self.s[start..self.i]).ok()
    }

    /// Returns the next argument: a `@capture`, a word, or a quoted string.
    fn next_arg(&mut self) -> Option<&'a str> {
        self.skip_ws();
        if self.i >= self.s.len() {
            return None;
        }
        if self.s[self.i] == b'"' {
            // Caller probably wants `next_string_literal` instead; defer.
            return None;
        }
        self.next_word()
    }

    /// Returns the next double-quoted string literal (with escape decoding),
    /// or `None` if the next non-whitespace token isn't a string.
    fn next_string_literal(&mut self) -> Option<String> {
        self.skip_ws();
        if self.i >= self.s.len() || self.s[self.i] != b'"' {
            return None;
        }
        self.i += 1;
        let mut out = Vec::new();
        while self.i < self.s.len() {
            match self.s[self.i] {
                b'\\' if self.i + 1 < self.s.len() => {
                    let next = self.s[self.i + 1];
                    out.push(match next {
                        b'n' => b'\n',
                        b't' => b'\t',
                        b'r' => b'\r',
                        // For any other escape, keep the literal char as-is.
                        c => c,
                    });
                    self.i += 2;
                }
                b'"' => {
                    self.i += 1;
                    return String::from_utf8(out).ok();
                }
                c => {
                    out.push(c);
                    self.i += 1;
                }
            }
        }
        // Unterminated string — give up to be safe.
        None
    }
}

/// A collection of [`TSQueryCapture`]s from a [`tree_sitter::QueryMatch`].
pub type QueryMatch<T> = Vec<TSQueryCapture<T>>;

/// A stateful struct for iterating over a tree-sitter query's matches.
pub struct TSQueryCursor<'a, 'tree>
where
    'tree: 'a,
{
    query: &'a tree_sitter::Query,
    capture_names: &'a [Arc<str>],
    cursor: MaybeOwnedMut<'a, tree_sitter::QueryCursor>,
    // A scratch IndexMap used to group captures with the same name.
    captures_scratch: IndexMap<u32, TSQueryCapture<tree_sitter::Node<'tree>>>,
}

/// A [`Cow`](std::borrow::Cow)-like enum holding either an owned or mutably borrowed [`T`].
//  Note: we internally use this to give the caller control over allocations when using a `TSQuery`.
enum MaybeOwnedMut<'a, T> {
    Borrowed(&'a mut T),
    Owned(T),
}

impl<'a, 'tree> TSQueryCursor<'a, 'tree> {
    /// Iterate over all the tree-sitter query matches in the order that they were found.
    ///
    /// ***Note:*** Because multiple patterns can match the same set of nodes, one match may contain captures
    /// that appear before _(i.e. the source text location)_ some of the captures from a previous match.
    pub fn matches(
        &'a mut self,
        node: tree_sitter::Node<'tree>,
        text: &'tree str,
        timeout: Option<Duration>,
    ) -> impl Iterator<Item = QueryMatch<tree_sitter::Node<'tree>>> + 'a {
        let cursor = match &mut self.cursor {
            MaybeOwnedMut::Borrowed(cursor) => cursor,
            MaybeOwnedMut::Owned(cursor) => cursor,
        };
        cursor.set_timeout_micros(timeout.map(|t| t.as_micros()).unwrap_or_default() as u64);
        let matches = cursor.matches(self.query, node, text.as_bytes());
        matches.map_deref(|q_match| {
            for capture in q_match.captures {
                self.captures_scratch
                    .entry(capture.index)
                    .and_modify(|qc| qc.push(capture.node))
                    .or_insert_with(|| {
                        let name = Arc::clone(&self.capture_names[capture.index as usize]);
                        // --- If the quantifier is either `+` or `*`, start with an array:
                        // (comment)+ @cap              TSCaptureContent::Multi
                        //
                        // Otherwise, use a scalar:
                        // (comment)  @cap              TSCaptureContent::Single
                        let quantifiers = self.query.capture_quantifiers(q_match.pattern_index);
                        let contents = if matches!(
                            quantifiers[capture.index as usize],
                            CaptureQuantifier::OneOrMore | CaptureQuantifier::ZeroOrMore
                        ) {
                            TSCaptureContent::Multi(vec![capture.node])
                        } else {
                            TSCaptureContent::Single(capture.node)
                        };
                        TSQueryCapture::<tree_sitter::Node> { name, contents }
                    });
            }
            self.captures_scratch
                .drain(..)
                .map(|(_, query_capture)| query_capture)
                .collect::<Vec<_>>()
        })
    }
}

/// An intermediate struct that normalizes a result from a [`tree_sitter::QueryMatch`].
/// It contains the `name` of the capture, as well as data for either:
/// * a single node ([`tree_sitter::QueryCapture`])
/// * multiple nodes ([`tree_sitter::QueryCaptures`])
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct TSQueryCapture<T> {
    pub name: Arc<str>,
    pub contents: TSCaptureContent<T>,
}

impl<T> TSQueryCapture<T> {
    /// Adds a [`T`] as a capture.
    pub fn push(&mut self, value: T) {
        if let TSCaptureContent::Multi(caps) = &mut self.contents {
            caps.push(value);
            return;
        }
        // Otherwise, we need to upgrade the `Single` to a `Multi`.
        let single = std::mem::replace(
            &mut self.contents,
            TSCaptureContent::Multi(Vec::with_capacity(2)),
        );
        let TSCaptureContent::Single(prior_value) = single else {
            unreachable!()
        };
        let TSCaptureContent::Multi(vec) = &mut self.contents else {
            unreachable!()
        };
        vec.push(prior_value);
        vec.push(value);
    }

    /// Creates a new `TsQueryCapture` that is a `SingleCapture`.
    pub fn new_single(name: Arc<str>, value: T) -> TSQueryCapture<T> {
        let contents = TSCaptureContent::<T>::Single(value);
        Self { name, contents }
    }

    /// Creates a new `TsQueryCapture` that is a `MultiCapture`.
    pub fn new_multi(name: Arc<str>, value: impl Into<Vec<T>>) -> TSQueryCapture<T> {
        let contents = TSCaptureContent::<T>::Multi(value.into());
        Self { name, contents }
    }
}

/// An enum describing whether a named capture has one or many captured nodes.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum TSCaptureContent<T> {
    Single(T),
    Multi(Vec<T>),
}

// Get all the match nodes based on a query. For each match, we build a `MatchNode`
// object. This object is deserialized and this is what is passed to the visit function.
// This is the first argument of the visit function.
// This `MatchNode` must have the captures and captures_list attributes that contains
// the values of the captures for the match.
//
// Note that we also add the context to the node that consists of the code and variables.
pub fn get_query_nodes(
    tree: &tree_sitter::Tree,
    query: &TSQuery,
    filename: &str,
    code: &str,
    arguments: &HashMap<String, String>,
) -> Vec<MatchNode> {
    let mut match_nodes: Vec<MatchNode> = vec![];

    for query_match in query.cursor().matches(tree.root_node(), code, None) {
        let mut captures: HashMap<String, TreeSitterNode> = HashMap::new();
        let mut captures_list: HashMap<String, Vec<TreeSitterNode>> = HashMap::new();
        for capture in query_match {
            let list = match capture.contents {
                TSCaptureContent::Single(node) => {
                    map_node(node).map(|n| vec![n]).unwrap_or_default()
                }
                TSCaptureContent::Multi(nodes) => {
                    nodes.into_iter().filter_map(map_node).collect::<Vec<_>>()
                }
            };
            // All captures are inserted into `captures_list`. However, the prior implementation continually
            // called `insert` on the `captures` map, which ended up re-writing the value every time.
            // Thus, to match this behavior, we take the `last` element of the list to insert into `captures`.
            if let Some(last) = list.last() {
                captures.insert(capture.name.to_string(), last.clone());
                captures_list.insert(capture.name.to_string(), list);
            }
        }

        if !captures.is_empty() {
            match_nodes.push(MatchNode {
                captures: captures.clone(),
                captures_list: captures_list.clone(),
                context: MatchNodeContext {
                    code: Some(code.to_string()),
                    filename: filename.to_string(),
                    arguments: arguments.clone(),
                },
            });
        }
    }
    match_nodes
}

// map a node from the tree-sitter representation into our own internal representation
// this is the representation that is passed to the JavaScript layer and how we represent
// or expose the node to the end-user.
pub fn map_node(node: tree_sitter::Node) -> Option<TreeSitterNode> {
    fn map_node_internal(
        cursor: &mut tree_sitter::TreeCursor,
        only_named_node: bool,
    ) -> Option<TreeSitterNode> {
        // we do not map space, parenthesis and other non-named nodes if there
        // when `only_named_node` is true (which is `true` for children only).
        if only_named_node && !cursor.node().is_named() {
            return None;
        }

        // map all the children as we should
        let mut children: Vec<TreeSitterNode> = vec![];
        if cursor.goto_first_child() {
            loop {
                // For the child, we only want to capture named nodes to avoid polluting the AST.
                let maybe_child = map_node_internal(cursor, true);
                if let Some(child) = maybe_child {
                    children.push(child);
                }
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
            cursor.goto_parent();
        }

        // finally, build the return value.
        let ts_node = TreeSitterNode {
            ast_type: cursor.node().kind().to_string(),
            start: Position {
                line: u32::try_from(cursor.node().range().start_point.row + 1).unwrap(),
                col: u32::try_from(cursor.node().range().start_point.column + 1).unwrap(),
            },
            end: Position {
                line: u32::try_from(cursor.node().range().end_point.row + 1).unwrap(),
                col: u32::try_from(cursor.node().range().end_point.column + 1).unwrap(),
            },
            field_name: cursor.field_name().map(ToString::to_string),
            children,
        };

        Some(ts_node)
    }

    let mut ts_cursor = node.walk();

    // Initially, we capture both un/named nodes to allow capturing unnamed node from
    // the tree-sitter query.
    map_node_internal(&mut ts_cursor, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_python_get_tree() {
        let source_code = r#"
arr = ["foo", "bar"];

def func():
   pass;"#;
        let t = get_tree(source_code, &Language::Python);
        assert!(t.is_some());
        assert_eq!("module", t.unwrap().root_node().kind());
    }

    #[test]
    fn test_map_node_simple() {
        let source_code = r#"
arr = ["foo", "bar"];

def func():
   pass;"#;
        let t = get_tree(source_code, &Language::Python);
        assert!(t.is_some());
        let tree_node = map_node(t.unwrap().root_node());
        assert!(tree_node.is_some());
        let root = tree_node.unwrap();
        assert_eq!(2, root.children.len());
        assert_eq!(
            "expression_statement",
            root.children.get(0).unwrap().ast_type
        );
        assert_eq!(
            "function_definition",
            root.children.get(1).unwrap().ast_type
        );
        assert!(root.children.get(1).unwrap().field_name.is_none());
        let function_definition = root.children.get(1).unwrap();
        assert_eq!(
            "name",
            function_definition
                .children
                .get(0)
                .unwrap()
                .field_name
                .clone()
                .unwrap()
        );
    }

    #[test]
    fn test_csharp_get_tree() {
        let source_code = r#"
namespace HelloWorld
{
    class Hello {
        static void Main(string[] args)
        {
            System.Console.WriteLine("Hello World!");
        }
    }
}
"#;
        let t = get_tree(source_code, &Language::Csharp);
        assert!(t.is_some());
        assert_eq!("compilation_unit", t.unwrap().root_node().kind());
    }

    #[test]
    fn test_dockerfile_get_tree() {
        let source_code = r#"
RUN /blabla
"#;
        let t = get_tree(source_code, &Language::Dockerfile);
        assert!(t.is_some());
        assert_eq!("source_file", t.unwrap().root_node().kind());
    }

    #[test]
    fn test_go_test_tree() {
        let source_code = r#"
package main
import "fmt"
func main() {
    fmt.Println("hello world")
}
"#;
        let t = get_tree(source_code, &Language::Go);
        assert!(t.is_some());
        assert_eq!("source_file", t.unwrap().root_node().kind());
    }

    #[test]
    fn test_java_get_tree() {
        let source_code = r#"
class Foo {
}
"#;
        let t = get_tree(source_code, &Language::Java);
        assert!(t.is_some());
        assert_eq!("program", t.unwrap().root_node().kind());
    }

    #[test]
    fn test_javascript_get_tree() {
        let source_code = r#"
function foo() {console.log("bar");}"#;
        let t = get_tree(source_code, &Language::JavaScript);
        assert!(t.is_some());
        assert_eq!("program", t.unwrap().root_node().kind());
    }

    #[test]
    fn test_json_get_tree() {
        let source_code = r#"
{}"#;
        let t = get_tree(source_code, &Language::Json);
        assert!(t.is_some());
        assert_eq!("document", t.unwrap().root_node().kind());
    }

    #[test]
    fn test_dart_get_tree() {
        let source_code = r#"void main() {
  print('Hello, Dart!');
}
"#;
        let t = get_tree(source_code, &Language::Dart);
        assert!(t.is_some());
        assert_eq!("program", t.unwrap().root_node().kind());
    }

    #[test]
    fn test_ruby_get_tree() {
        let source_code = r#"def greeting
  puts "Hello Ruby!"
  return
end

greeting()
"#;
        let t = get_tree(source_code, &Language::Ruby);
        assert!(t.is_some());
        assert_eq!("program", t.unwrap().root_node().kind());
    }

    #[test]
    fn test_rust_get_tree() {
        let source_code = r#"
fn foo(bar: String) -> String {
   return "foobar".to_string();
}
"#;
        let t = get_tree(source_code, &Language::Rust);
        assert!(t.is_some());
        assert_eq!("source_file", t.unwrap().root_node().kind());
    }

    #[test]
    fn test_kotlin_get_tree() {
        let source_code = r#"
fun main() {
    println("What's your name?")
    val name = readln()
    println("Hello, $name!")
}
"#;
        let t = get_tree(source_code, &Language::Kotlin);
        assert!(t.is_some());
        assert_eq!("source_file", t.unwrap().root_node().kind());
    }

    #[test]
    fn test_swift_get_tree() {
        let source_code = r#"
// HelloWorld.swift
import Foundation
print("Hello, World!")

"#;
        let t = get_tree(source_code, &Language::Swift);
        assert!(t.is_some());
        assert_eq!("source_file", t.unwrap().root_node().kind());
    }

    #[test]
    fn test_typescript_get_tree() {
        let source_code = r#"
let myAdd = function (x: number, y: number): number {
  return x + y;
};
"#;
        let t = get_tree(source_code, &Language::TypeScript);
        assert!(t.is_some());
        assert_eq!("program", t.unwrap().root_node().kind());
    }

    #[test]
    fn test_yaml_get_tree() {
        let source_code = r#"
rulesets:
  - my-ruleset
"#;
        let t = get_tree(source_code, &Language::Yaml);
        assert!(t.is_some());
        assert_eq!("stream", t.unwrap().root_node().kind());
    }

    #[test]
    fn test_starlark_get_tree() {
        let source_code = r#"
load("@io_bazel_rules_docker//container:container.bzl", "container_image")
container_image(
    name = "base",
    base = "@io_bazel_rules_docker//images/ubuntu-1604:latest",
)
"#;
        let t = get_tree(source_code, &Language::Starlark);
        assert!(t.is_some());
        assert_eq!("module", t.unwrap().root_node().kind());
    }

    #[test]
    fn test_bash_get_tree() {
        let source_code = r#"
echo "Hello, World!"
"#;
        let t = get_tree(source_code, &Language::Bash);
        assert!(t.is_some());
        assert_eq!("program", t.unwrap().root_node().kind());
    }

    #[test]
    fn test_php_get_tree() {
        let source_code = r#"
<?php
echo "Hello, World!";
?>
"#;
        let t = get_tree(source_code, &Language::PHP);
        assert!(t.is_some());
        let t = t.unwrap();
        assert!(!t.root_node().has_error());
        assert_eq!("program", t.root_node().kind());
    }

    #[test]
    fn test_markdown_get_tree() {
        let source_code = r#"
# Hello, World!
This is some text
"#;
        let t = get_tree(source_code, &Language::Markdown);
        assert!(t.is_some());
        let t = t.unwrap();
        assert!(!t.root_node().has_error());
        assert_eq!("document", t.root_node().kind());
    }

    #[test]
    fn test_apex_get_tree() {
        let source_code = r#"
public class HelloWorld {
    public static void main() {
        System.out.println('Hello, World');
    }
}"#;
        let t = get_tree(source_code, &Language::Apex);
        assert!(t.is_some());
        let t = t.unwrap();
        assert!(!t.root_node().has_error());
        assert_eq!("parser_output", t.root_node().kind());
    }

    #[test]
    fn test_r_get_tree() {
        let source_code = r#"
x <- 1
print("Hello, World!")
"#;
        let t = get_tree(source_code, &Language::R);
        assert!(t.is_some());
        let t = t.unwrap();
        assert!(!t.root_node().has_error());
        assert_eq!("program", t.root_node().kind());
    }

    #[test]
    fn test_elixir_get_tree() {
        let source_code = r#"
defmodule Sum do
  def add(a, b) do
    a + b
  end
end
"#;
        let t = get_tree(source_code, &Language::Elixir);
        assert!(t.is_some());
        let t = t.unwrap();
        assert!(!t.root_node().has_error());
        assert_eq!("source", t.root_node().kind());
    }

    #[test]
    fn test_sql_get_tree() {
        let source_code = r#"
SELECT * FROM table WHERE column = 'value';
"#;
        let t = get_tree(source_code, &Language::SQL);
        assert!(t.is_some());
        let t = t.unwrap();
        assert!(!t.root_node().has_error());
        assert_eq!("program", t.root_node().kind());
    }

    // test the number of node we should retrieve when executing a rule
    #[test]
    fn test_get_query_nodes() {
        let q = r#"
(class_definition
  name: (identifier) @classname
  superclasses: (argument_list
    (identifier)+ @superclasses
  )
)
        "#;

        let c = r#"
 class myClass(Parent):
    def __init__(self):
        pass
        "#;

        let tree = get_tree(c, &Language::Python).unwrap();
        let query = get_query(q, &Language::Python).expect("query defined");
        let query_nodes = get_query_nodes(&tree, &query, "myfile.py", c, &HashMap::new());
        assert_eq!(query_nodes.len(), 1);
        let query_node = query_nodes.get(0).unwrap();
        assert_eq!(2, query_node.captures_list.len());
        assert_eq!(1, query_node.captures_list.get("classname").unwrap().len());
        assert_eq!(
            1,
            query_node.captures_list.get("superclasses").unwrap().len()
        );
        assert_eq!(2, query_node.captures.len());
        assert!(query_node.captures.contains_key("superclasses"));
        let superclasses = query_node.captures.get("superclasses").unwrap();
        assert_eq!(2, superclasses.start.line);
        assert_eq!(16, superclasses.start.col);
        assert_eq!(2, superclasses.end.line);
        assert_eq!(22, superclasses.end.col);
        assert_eq!("identifier", superclasses.ast_type);
        assert_eq!(None, superclasses.field_name);
        assert!(query_node.captures.contains_key("classname"));
    }
}

#[cfg(test)]
mod literal_pre_screen_tests {
    use super::*;

    #[test]
    fn empty_query_yields_trivial_screen() {
        let s = LiteralPreScreen::extract("(identifier) @x", 1);
        assert!(s.is_trivial());
        assert!(s.matches("anything"));
    }

    #[test]
    fn eq_predicate_extracted() {
        // `#eq? @cap "literal"` -> requires "literal".
        let s = LiteralPreScreen::extract(
            r#"(call_expression function: (identifier) @id (#eq? @id "system"))"#,
            1,
        );
        assert!(!s.is_trivial());
        assert!(s.matches("import os; os.system('ls')"));
        assert!(!s.matches("hello world"));
    }

    #[test]
    fn any_of_predicate_extracted() {
        let s = LiteralPreScreen::extract(
            r#"(call_expression function: (_) @fn (#any-of? @fn "exec" "eval" "compile"))"#,
            1,
        );
        assert!(!s.is_trivial());
        assert!(s.matches("eval('1')"));
        assert!(s.matches("compile_my_thing()"));
        assert!(!s.matches("foo bar baz"));
    }

    #[test]
    fn multiple_eq_predicates_anded() {
        // Both literals required.
        let s = LiteralPreScreen::extract(
            r#"(call (id) @a (#eq? @a "foo") (id) @b (#eq? @b "bar"))"#,
            1,
        );
        assert!(s.matches("foo bar"));
        assert!(!s.matches("foo only"));
        assert!(!s.matches("bar only"));
    }

    #[test]
    fn negative_predicates_ignored() {
        // `#not-eq?` cannot screen by literal presence (it requires absence).
        let s = LiteralPreScreen::extract(r#"(call (id) @a (#not-eq? @a "foo"))"#, 1);
        assert!(s.is_trivial());
        assert!(s.matches("anything"));
    }

    #[test]
    fn match_predicate_extracts_literal_prefix() {
        // Anchored regex with literal prefix — we extract `^foo$` → "foo".
        let s = LiteralPreScreen::extract(r#"(id) @x (#match? @x "^foo$")"#, 1);
        assert!(!s.is_trivial());
        assert!(s.matches("foo"));
        assert!(!s.matches("bar"));
    }

    #[test]
    fn match_predicate_extracts_longest_run() {
        // The longest contiguous literal run wins.
        let s = LiteralPreScreen::extract(
            r#"(id) @x (#match? @x "gopkg.in/DataDog/dd-trace-go.v1/.*")"#,
            1,
        );
        assert!(!s.is_trivial());
        assert!(s.matches("import \"gopkg.in/DataDog/dd-trace-go.v1/ddtrace/tracer\""));
        assert!(!s.matches("package main\nfunc Foo() {}"));
    }

    #[test]
    fn match_predicate_decodes_escaped_specials() {
        // `\.fabric\.dog` should yield literal `.fabric.dog`.
        let s = LiteralPreScreen::extract(r#"(id) @x (#match? @x "^.*\.fabric\.dog.*$")"#, 1);
        assert!(!s.is_trivial());
        assert!(s.matches("hello.fabric.dog world"));
        assert!(!s.matches("hello.world"));
    }

    #[test]
    fn match_predicate_bails_on_alternation() {
        // Top-level `|` → each branch has its own requirements; bail.
        let s = LiteralPreScreen::extract(r#"(id) @x (#match? @x "foo|bar|baz")"#, 1);
        assert!(s.is_trivial());
    }

    #[test]
    fn match_predicate_bails_on_group_modifier() {
        // `(?i)` makes the literal case-insensitive — we'd extract wrong case.
        let s = LiteralPreScreen::extract(r#"(id) @x (#match? @x "(?i)foo")"#, 1);
        assert!(s.is_trivial());
    }

    #[test]
    fn match_predicate_bails_when_no_long_enough_run() {
        // Longest literal run of 2 chars or less → too generic, bail.
        let s = LiteralPreScreen::extract(r#"(id) @x (#match? @x "a.b.c.d")"#, 1);
        assert!(s.is_trivial());
    }

    #[test]
    fn match_predicate_decodes_escaped_slash() {
        // `\/` is the regex-escape for `/` (legal in some flavors).
        let s = LiteralPreScreen::extract(r#"(id) @x (#match? @x "^prefix\/path\/.*$")"#, 1);
        assert!(!s.is_trivial());
        assert!(s.matches("prefix/path/anything"));
    }

    // -- multi-pattern tests (use a real tree-sitter Query) ---------------
    use crate::analysis::tree_sitter::get_tree_sitter_language;
    use crate::model::common::Language;

    fn screen_for_go_query(src: &str) -> LiteralPreScreen {
        let lang = get_tree_sitter_language(&Language::Go);
        let q = tree_sitter::Query::new(&lang, src).unwrap();
        LiteralPreScreen::extract_from_query(&q, src)
    }

    #[test]
    fn multi_pattern_both_constrained_unlocks_screen() {
        // Two top-level patterns; each constrains a literal. File must
        // contain at least one of the two literals to possibly match.
        let src = r#"
(import_spec
    path: (interpreted_string_literal) @import.path
    (#match? @import.path "gopkg.in/DataDog/dd-trace-go.v1/.*")
) @import
(selector_expression
    operand: (identifier)
    field: (field_identifier) @func.name
    (#eq? @func.name "WithServiceName")
) @call
"#;
        let s = screen_for_go_query(src);
        assert!(!s.is_trivial());
        assert!(s.matches("// uses WithServiceName here\n"));
        assert!(s.matches("// uses gopkg.in/DataDog/dd-trace-go.v1/ddtrace\n"));
        // No literal → file safely skipped.
        assert!(!s.matches("package main\nfunc Foo() {}\n"));
    }

    #[test]
    fn multi_pattern_one_unconstrained_bails() {
        // First pattern requires `Foo`; second matches ANY function call.
        // Because pattern 2 can match arbitrary code, the rule can match
        // arbitrary code, so we must bail.
        let src = r#"
(call_expression
  function: (identifier) @fn
  (#eq? @fn "Foo")
) @first
(call_expression) @anycall
"#;
        let s = screen_for_go_query(src);
        assert!(
            s.is_trivial(),
            "unconstrained second pattern must force bail"
        );
        assert!(s.matches("anything goes"));
    }

    #[test]
    fn multi_pattern_alternation_bracket_in_one_pattern_bails() {
        // Even if other patterns are clean, an internal `[...]` in one
        // pattern is unsafe — we don't know which branch's predicates apply.
        let src = r#"
(call_expression
  function: (identifier) @fn
  (#eq? @fn "safe")
) @first
(_
  [(assignment_statement) (interpreted_string_literal)] @lit
) @second
"#;
        let s = screen_for_go_query(src);
        assert!(s.is_trivial());
    }

    #[test]
    fn capture_to_capture_eq_ignored() {
        // `#eq? @a @b` cannot reduce to a literal screen.
        let s = LiteralPreScreen::extract(r#"(call (id) @a (id) @b (#eq? @a @b))"#, 1);
        assert!(s.is_trivial());
    }

    #[test]
    fn multi_pattern_extract_skipped_in_single_pattern_helper() {
        // The single-pattern test helper bails when called with pattern_count > 1.
        let s = LiteralPreScreen::extract(r#"((id) @a (#eq? @a "foo")) ((id) @b)"#, 2);
        assert!(s.is_trivial());
    }

    #[test]
    fn comments_skipped() {
        let s = LiteralPreScreen::extract("; (#eq? @x \"trap\")\n(id) @x (#eq? @x \"real\")", 1);
        assert!(s.matches("real"));
        assert!(!s.matches("trap"));
    }

    #[test]
    fn escaped_quotes_in_string_literal() {
        let s = LiteralPreScreen::extract(r#"(id) @x (#eq? @x "say \"hi\"")"#, 1);
        assert!(s.matches(r#"say "hi""#));
        assert!(!s.matches("hello"));
    }

    #[test]
    fn paren_inside_string_does_not_break_paren_matching() {
        // The `)` inside the string must not close the predicate.
        let s = LiteralPreScreen::extract(r#"(id) @x (#eq? @x "weird)stuff") (id) @y"#, 1);
        assert!(s.matches("weird)stuff"));
        assert!(!s.matches("nothing here"));
    }

    #[test]
    fn always_match_when_no_literals() {
        assert!(LiteralPreScreen::always_match().matches(""));
        assert!(LiteralPreScreen::always_match().matches("xyz"));
    }
}

#[cfg(test)]
mod alternation_and_quantifier_tests {
    use super::*;

    #[test]
    fn alternation_query_yields_trivial_screen() {
        // Real-world `go-security/command-injection` shape: `[A B]@cap`. With
        // depth-tracking we now skip the predicates inside the alternation
        // (so each branch's literal is not required across both branches),
        // ending up with no AND-groups → always-match.
        let q = r#"
[
    (call_expression
        function: (selector_expression
            field: (field_identifier) @command
        )
        (#eq? @command "Command")
    )
    (call_expression
        function: (selector_expression
            field: (field_identifier) @commandcontext
        )
        (#eq? @commandcontext "CommandContext")
    )
]@call
"#;
        let s = LiteralPreScreen::extract(q, 1);
        assert!(
            s.is_trivial(),
            "alternation query must NOT extract literals"
        );
        assert!(s.matches("exec.CommandContext(ctx, \"ls\")"));
        assert!(s.matches("package main"));
    }

    #[test]
    fn predicate_in_optional_group_is_skipped() {
        // `(...)?` makes its contents optional — predicates inside aren't
        // unconditionally required, so we must skip them.
        let q = r#"
(function_definition
    body: (block
        (expression_statement
            (assignment
                left: (identifier) @v
                (#eq? @v "foo")
            )
        )?
        (call (identifier) @id (#eq? @id "bar"))
    )
)
"#;
        let s = LiteralPreScreen::extract(q, 1);
        // "foo" inside the optional group must NOT be extracted, but "bar"
        // outside it should be.
        assert!(!s.is_trivial());
        assert!(s.matches("bar()"));
        assert!(!s.matches("baz only"));
    }

    #[test]
    fn top_level_predicate_outside_alternation_extracted() {
        // The python-flask/cookie-injection shape: a `[A B]` alternation
        // appears in the query, but separately at depth 0 we have a
        // `#eq? @id "set_cookie"` predicate. That literal IS required for
        // the rule to match.
        let q = r#"
(function_definition
  (parameters (identifier) @_param)
  (block
    (expression_statement
      (assignment
        left: (identifier) @_taint
        right: [
          (identifier) @_paramusage
          (call (argument_list (identifier) @_paramusage))
        ]
      )
    )
    (expression_statement
      (call
        function: (attribute
          attribute: (identifier) @id
          (#eq? @id "set_cookie")
        )
      )
    )
  )
)
"#;
        let s = LiteralPreScreen::extract(q, 1);
        assert!(!s.is_trivial());
        assert!(s.matches("resp.set_cookie(\"k\", v)"));
        assert!(!s.matches("resp.headers['X-Foo'] = 'bar'"));
    }
}
