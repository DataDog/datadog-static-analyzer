//! A "combined" tree-sitter query that fuses all rules' patterns for a given
//! language into a single multi-pattern query, walked once per file. Matches
//! are bucketed back to per-rule via a `pattern_index → rule_idx` mapping.
//!
//! # Why
//!
//! Each rule's per-rule TS query independently walks the parse tree. For
//! large workloads this duplicates a lot of traversal work — visit a
//! `function_definition` once for each rule that targets it. A combined
//! query lets tree-sitter walk the tree once and emit matches for whichever
//! patterns fire at each node.
//!
//! # Caveats
//!
//! - Up-front cost: building the combined query (a single big `Query::new`
//!   call) is O(total query source bytes). This dominates on small repos
//!   where the combined query is built but only a few files are scanned.
//!   Callers should adapt: only use combined-query path when
//!   `file_count × rule_count` exceeds a threshold.
//! - Capture-name space: tree-sitter dedupes capture names across patterns,
//!   so `@id` from rule A and `@id` from rule B share an index in the
//!   combined query. Each match carries its own pattern index, and a
//!   match's captures only come from the firing pattern, so dispatching
//!   per `pattern_index → rule_idx` automatically isolates each rule's
//!   captures by name from JS's perspective.
//! - The combined query inherits all the per-rule pre-screen logic; we
//!   don't run it on files that the rule's existing `LiteralPreScreen`
//!   would have rejected.

use crate::analysis::tree_sitter::{QueryMatch, TSQuery, TSQueryCapture, TSCaptureContent};
use crate::model::rule::RuleInternal;
use indexmap::IndexMap;
use std::sync::Arc;
use streaming_iterator::StreamingIterator;
use tree_sitter::CaptureQuantifier;

/// A combined Tree-sitter query covering many rules' patterns at once.
pub struct CombinedQuery {
    /// The single combined `tree_sitter::Query`.
    query: tree_sitter::Query,
    /// Capture names (Arc'd for cheap cloning), indexed by capture id within
    /// the combined query.
    capture_names: Vec<Arc<str>>,
    /// `pattern_to_rule_idx[i]` is the index (in the input rule slice) of
    /// the rule that contributed pattern `i` of the combined query. A rule
    /// with a multi-pattern query contributes consecutive entries.
    pattern_to_rule_idx: Vec<usize>,
    /// Total rule count (= original `rules.len()`). Used to size buckets.
    rule_count: usize,
}

impl CombinedQuery {
    /// Build a combined query from each rule's tree-sitter source. Returns
    /// `None` if construction fails (we then fall back to per-rule path).
    ///
    /// Each rule's query may itself have multiple top-level patterns, so we
    /// compile it standalone first to count its patterns. The combined query
    /// is then `<rule0_source>\n<rule1_source>\n...`.
    pub fn try_new(
        rules: &[RuleInternal],
        ts_language: &tree_sitter::Language,
    ) -> Option<Self> {
        let mut combined_source = String::new();
        let mut pattern_to_rule_idx: Vec<usize> = Vec::new();
        for (rule_idx, rule) in rules.iter().enumerate() {
            // Skip rules whose source we don't have (defensive: shouldn't
            // happen for production rules from `to_rule_internal`).
            if rule.tree_sitter_query_source.is_empty() {
                return None;
            }
            // Compile per-rule first to count its top-level patterns.
            let single = tree_sitter::Query::new(ts_language, &rule.tree_sitter_query_source).ok()?;
            let n = single.pattern_count();
            for _ in 0..n {
                pattern_to_rule_idx.push(rule_idx);
            }
            combined_source.push_str(&rule.tree_sitter_query_source);
            combined_source.push('\n');
        }
        let query = tree_sitter::Query::new(ts_language, &combined_source).ok()?;
        if query.pattern_count() != pattern_to_rule_idx.len() {
            // Pattern accounting mismatch — refuse to use the combined query.
            return None;
        }
        let capture_names: Vec<Arc<str>> = query
            .capture_names()
            .iter()
            .map(|&n| Arc::from(n))
            .collect();
        Some(Self {
            query,
            capture_names,
            pattern_to_rule_idx,
            rule_count: rules.len(),
        })
    }

    /// Run the combined query against `tree` / `code` and return a
    /// `Vec<Vec<QueryMatch>>` indexed by rule_idx. Empty inner Vecs for
    /// rules with no matches.
    pub fn matches_per_rule<'tree>(
        &self,
        node: tree_sitter::Node<'tree>,
        text: &'tree str,
        timeout: Option<std::time::Duration>,
        cursor: &mut tree_sitter::QueryCursor,
    ) -> Vec<Vec<QueryMatch<tree_sitter::Node<'tree>>>> {
        cursor.set_timeout_micros(
            timeout
                .map(|t| t.as_micros())
                .unwrap_or_default() as u64,
        );
        let mut buckets: Vec<Vec<QueryMatch<tree_sitter::Node<'tree>>>> =
            vec![Vec::new(); self.rule_count];
        // Reusable scratch IndexMap for grouping captures with the same
        // index within a single match (mirroring `TSQueryCursor::matches`).
        let mut captures_scratch: IndexMap<u32, TSQueryCapture<tree_sitter::Node<'tree>>> =
            IndexMap::new();
        let mut iter = cursor.matches(&self.query, node, text.as_bytes());
        while let Some(q_match) = iter.next() {
            let pattern_index = q_match.pattern_index;
            for capture in q_match.captures {
                captures_scratch
                    .entry(capture.index)
                    .and_modify(|qc| qc.push(capture.node))
                    .or_insert_with(|| {
                        let name = Arc::clone(&self.capture_names[capture.index as usize]);
                        let quantifiers = self.query.capture_quantifiers(pattern_index);
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
            let captures: Vec<TSQueryCapture<tree_sitter::Node>> = captures_scratch
                .drain(..)
                .map(|(_, qc)| qc)
                .collect();
            if captures.is_empty() {
                continue;
            }
            let rule_idx = self.pattern_to_rule_idx[pattern_index];
            buckets[rule_idx].push(captures);
        }
        buckets
    }
}

// Note: TSCaptureContent and TSQueryCapture are public types from
// `crate::analysis::tree_sitter`. The fields are public, so we can
// construct them here.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::tree_sitter::get_tree_sitter_language;
    use crate::model::common::Language;
    use crate::model::rule::{RuleCategory, RuleSeverity};

    fn mk_rule(name: &str, ts: &str, language: Language) -> RuleInternal {
        RuleInternal {
            name: name.to_string(),
            short_description: None,
            description: None,
            category: RuleCategory::Unknown,
            severity: RuleSeverity::None,
            language,
            code: "function visit() {}".to_string(),
            tree_sitter_query: TSQuery::try_new(&get_tree_sitter_language(&language), ts).unwrap(),
            tree_sitter_query_source: ts.to_string(),
        }
    }

    #[test]
    fn builds_combined_query() {
        let lang = Language::Go;
        let ts_lang = get_tree_sitter_language(&lang);
        let rules = vec![
            mk_rule("a", "(call_expression) @c", lang),
            mk_rule("b", "(identifier) @id", lang),
        ];
        let combined = CombinedQuery::try_new(&rules, &ts_lang).unwrap();
        // 2 rules, each with 1 pattern → 2 combined patterns.
        assert_eq!(combined.pattern_to_rule_idx, vec![0, 1]);
    }

    #[test]
    fn dispatches_matches_to_correct_rules() {
        let lang = Language::Go;
        let ts_lang = get_tree_sitter_language(&lang);
        let rules = vec![
            mk_rule("calls", "(call_expression) @c", lang),
            mk_rule("idents", "(identifier) @i", lang),
        ];
        let combined = CombinedQuery::try_new(&rules, &ts_lang).unwrap();

        let code = "package main\nfunc Foo() { Bar() }";
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&ts_lang).unwrap();
        let tree = parser.parse(code, None).unwrap();

        let mut cursor = tree_sitter::QueryCursor::new();
        let buckets = combined.matches_per_rule(tree.root_node(), code, None, &mut cursor);
        assert_eq!(buckets.len(), 2);
        // The exact match counts depend on grammar specifics, but both rules
        // should find at least one match.
        assert!(!buckets[0].is_empty(), "rule `calls` should have matches");
        assert!(!buckets[1].is_empty(), "rule `idents` should have matches");
    }
}
