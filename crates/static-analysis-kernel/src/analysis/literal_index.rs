//! Multi-pattern literal scanner for the file-level pre-screen.
//!
//! At static-analysis startup, we collect every literal across every rule's
//! `LiteralPreScreen` for a given language and build a single Aho-Corasick
//! automaton from them. Per file, one O(file_size) scan populates a small
//! HashSet of literals known to be present, which the per-rule pre-screen
//! check then uses for O(1) lookup instead of O(file_size) `code.contains`
//! per literal.
//!
//! On dd-source: ~63 rules × ~5-10 literals each = a few hundred literals,
//! and a single AC scan replaces ~hundreds of memchr scans per file.

use crate::model::rule::RuleInternal;
use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use std::collections::HashSet;

/// Per-language literal index: the Aho-Corasick automaton, plus a flat list
/// of the literal strings indexed by AC pattern_id (so we can recover the
/// matched substring during a scan).
pub struct LiteralIndex {
    ac: AhoCorasick,
    literals: Vec<String>,
}

impl LiteralIndex {
    /// Build the index from every literal referenced in any rule's
    /// `LiteralPreScreen`. Returns `None` if the rule list has zero
    /// literals (every rule is "always-match"); callers should fall back
    /// to the per-literal `code.contains` path in that case.
    pub fn build(rules: &[RuleInternal]) -> Option<Self> {
        let mut seen: HashSet<String> = HashSet::new();
        let mut literals: Vec<String> = Vec::new();
        for rule in rules {
            for lit in rule.tree_sitter_query.pre_screen().iter_literals() {
                if seen.insert(lit.to_string()) {
                    literals.push(lit.to_string());
                }
            }
        }
        if literals.is_empty() {
            return None;
        }
        // Use Standard match-kind (required for overlapping iteration).
        // find_overlapping_iter emits a match for EVERY literal that occurs
        // at EVERY position, including overlaps. This is required because
        // some literals are substrings of others (e.g. one rule has "typ"
        // and another has "type"); non-overlapping iteration would emit
        // the shorter one and skip past, missing the longer one.
        let ac = AhoCorasickBuilder::new()
            .ascii_case_insensitive(false)
            .match_kind(aho_corasick::MatchKind::Standard)
            .build(&literals)
            .ok()?;
        Some(Self { ac, literals })
    }

    /// Scan `code` once and return the set of literal strings that appear
    /// in it. The returned `HashSet<&str>` borrows from `&self.literals`.
    pub fn present_in<'a>(&'a self, code: &str) -> HashSet<&'a str> {
        let mut present: HashSet<&'a str> = HashSet::with_capacity(self.literals.len() / 4);
        for mat in self.ac.find_overlapping_iter(code) {
            present.insert(self.literals[mat.pattern().as_usize()].as_str());
        }
        present
    }
}

#[cfg(test)]
mod overlap_test {
    use super::*;
    /// Regression: when one literal ("typ") is a prefix of another ("type")
    /// and a file contains the longer literal, AC must still report the
    /// longer one as present. With the default non-overlapping `find_iter`,
    /// the shorter "typ" would be emitted and "type" would be skipped.
    /// `find_overlapping_iter` correctly emits both.
    #[test]
    fn substring_literals_both_reported() {
        let ac = aho_corasick::AhoCorasickBuilder::new()
            .match_kind(aho_corasick::MatchKind::Standard)
            .build(["typ", "type"]).unwrap();
        let mut seen: HashSet<&str> = HashSet::new();
        for mat in ac.find_overlapping_iter("if type(x):") {
            seen.insert(if mat.pattern().as_usize() == 0 { "typ" } else { "type" });
        }
        assert!(seen.contains("typ"));
        assert!(seen.contains("type"));
    }
}
