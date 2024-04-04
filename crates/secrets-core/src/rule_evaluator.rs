// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::capture::{Capture, Captures};
use crate::matcher::{Matcher, MatcherError, MatcherId, PatternId, PatternMatch};
use crate::rule::{Expression, MatchSource, Rule, RuleId};
use bstr::BStr;
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::iter::FusedIterator;
use std::sync::Arc;

pub struct RuleEvaluator {
    /// A mapping from an id to its [`Rule`].
    rules: HashMap<RuleId, Arc<Rule>>,
    /// A mapping from an id to its [`Matcher`].
    // NOTE/TODO: this is a RefCell until [`Matcher`] can be refactored to use interior mutability.
    matchers: RefCell<HashMap<MatcherId, Matcher>>,

    /// The number of bytes this evaluator has instructed its Matchers to scan.
    bytes_scanned: Cell<usize>,
}

impl RuleEvaluator {
    pub fn new(matchers: impl Into<Vec<Matcher>>, rules: impl AsRef<[Arc<Rule>]>) -> RuleEvaluator {
        let rules = rules
            .as_ref()
            .iter()
            .map(|rule| (rule.id().clone(), Arc::clone(rule)))
            .collect::<HashMap<_, _>>();
        let matchers = matchers
            .into()
            .into_iter()
            .map(|matcher| (matcher.id(), matcher))
            .collect();
        Self {
            rules,
            matchers: RefCell::new(matchers),
            bytes_scanned: Cell::new(0),
        }
    }

    /// The total number of bytes this RuleEvaluator has scanned. As Matchers are instructed
    /// to scan a byte slice, this count increases.
    pub fn bytes_scanned(&self) -> usize {
        self.bytes_scanned.get()
    }

    /// Creates a stateful [`Scanner`] that can detect [`Rule`] matches for the given data source.
    pub fn scan<'a, 'd>(&'a self, data: &'d [u8]) -> Scanner<'a, 'd> {
        Scanner {
            state: RefCell::new(Default::default()),
            evaluator: self,
            data,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EvaluatorError {
    #[error("capture with name `{0}` does not exist")]
    UnknownCapture(String),
    #[error("capture `{0}` cannot be re-assigned")]
    CaptureReassignment(String),
    #[error(transparent)]
    Matcher(#[from] MatcherError),
}

/// Provides a cache containing a possibly unsorted list of [`PatternMatch`]s with possibly different [`PatternId`]s.
///
/// The reason the cached `PatternMatch` are stored in a vector is because we assume that
/// the vast majority of scans will not produce matches, and if they do, the number will be
/// small enough that iterating `O(n)` through this vector will likely outperform any
/// method that involves pre-processing (e.g. sorting, or HashMap-type data structures).
///
/// Because of the above choice, to be able to extract a vector of [`PatternMatch`] that
/// match what the caller is requesting, we need to be able to quickly remove an item from
/// the vector. Rather than implementing [`Default`] for [`PatternMatch`], we instead
/// wrap it in an `Option` so we can use `None` as the default,
///
/// Note: [`PatternMatch`] is semantically never "None", so the use of `Option` is purely
/// for performance, which is why it's hidden under a Vec-like interface.
#[derive(Debug, Default, Clone)]
struct MatchesCache<'d> {
    vec: Vec<Option<PatternMatch<'d>>>,
    remaining: usize,
}

impl<'d> MatchesCache<'d> {
    /// Instantiates a cache with at least the specified capacity.
    #[inline]
    pub fn with_capacity(capacity: usize) -> MatchesCache<'d> {
        Self {
            vec: Vec::with_capacity(capacity),
            remaining: 0,
        }
    }
}

impl<'d> MatchesCache<'d> {
    /// Iterates over all [`PatternMatch`] in the cache.
    pub fn iter(&self) -> impl Iterator<Item = &PatternMatch<'d>> {
        self.vec
            .iter()
            // Note: `self.remaining` will never change -- this is just to fuse without writing a custom iterator.
            .take_while(|_| self.remaining > 0)
            .flat_map(|pm| pm.as_ref())
    }

    /// Takes the next [`PatternMatch`] matching the [`PatternId`] from the cache.
    ///
    /// This operation has O(n) time complexity.
    #[inline]
    pub fn take_next(&mut self, pattern_id: PatternId) -> Option<PatternMatch<'d>> {
        if self.remaining == 0 {
            return None;
        }
        for slot in &mut self.vec {
            if matches!(slot, Some(pm) if pm.pattern_id() == pattern_id) {
                self.remaining -= 1;
                return slot.take();
            }
        }
        None
    }

    /// Pushes a new [`PatternMatch`] into the cache.
    #[inline]
    pub fn push(&mut self, pattern_match: PatternMatch<'d>) {
        self.vec.push(Some(pattern_match));
        self.remaining += 1;
    }

    /// Returns a reference to the next [`PatternMatch`] in the cache with the given `PatternId`.
    ///
    /// This operation has O(n) time complexity.
    pub fn peek(&self, pattern_id: PatternId) -> Option<&PatternMatch<'d>> {
        self.vec
            .iter()
            .map(|opt| opt.as_ref())
            .find(|&opt| opt.is_some_and(|pm| pm.pattern_id() == pattern_id))
            .flatten()
    }

    /// Returns the number of patterns in the cache.
    pub fn len(&self) -> usize {
        self.remaining
    }
}

#[derive(Debug, Clone)]
struct EvalItem<'d> {
    expr: Arc<Expression>,
    full_data: &'d [u8],
    data_slice: &'d [u8],
}

impl<'d> EvalItem<'d> {
    pub fn new(expr: Arc<Expression>, full_data: &'d [u8], data_slice: &'d [u8]) -> EvalItem<'d> {
        Self {
            expr,
            full_data,
            data_slice,
        }
    }

    pub fn from_parent(expr_rc: &Arc<Expression>, from: &Self) -> EvalItem<'d> {
        Self {
            expr: Arc::clone(expr_rc),
            full_data: from.full_data,
            data_slice: from.data_slice,
        }
    }
}

/// The result of a call to the recursive evaluation function.
#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone)]
enum Evaluated<'d> {
    /// A match where the evaluated [`Expression`] is a top-level [`IsMatch`](Expression::IsMatch).
    TopLevelMatch(PatternMatch<'d>),
    /// A match where the evaluated [`Expression`] is a not a [`TopLevelMatch`](Evaluated::TopLevelMatch).
    IntermediateMatch,
    /// A failed match
    NoMatch,
}

#[derive(Debug, Default, Clone)]
struct ScannerState<'d> {
    /// A scratch space used in a stateful manner during a rule evaluation by incrementally
    /// populating it with the captures that surface from the evaluation of each [`Expression`].
    captures_scratch: HashMap<String, Option<&'d [u8]>>,
    /// A scratch space for [`PatternMatch`]es while a rule evaluation is occurring. This is required
    /// because a single rule might have multiple top-level pattern matches, and we need to preserve
    /// them all because each can contain named captures that will go into the final `RuleMatch`.
    p_match_scratch: Vec<PatternMatch<'d>>,

    /// A cache to store a vector of [`PatternMatch`] from a single matcher's scan of an input data.
    /// This cache allows matchers to perform vectorized scans in a way that is abstracted
    /// away from the caller.
    scan_cache: HashMap<CacheKey, MatchesCache<'d>>,
}

pub struct Scanner<'a, 'd> {
    state: RefCell<ScannerState<'d>>,
    evaluator: &'a RuleEvaluator,
    data: &'d [u8],
}

impl<'a, 'd> Scanner<'a, 'd> {
    /// Scans the given `data`,
    pub fn rule(&'a self, rule_id: &RuleId) -> ScanIter<'a, 'd> {
        ScanIter {
            data: self.data,
            rule_id: rule_id.clone(),
            evaluator: self.evaluator,
            next_data_slice: self.data,
            step_index: 0,
            s: self,
        }
    }

    /// Clears the entire underlying [`PatternMatch`] cache, removing all keys and values.
    pub(crate) fn clear_cache(&mut self) {
        self.state.borrow_mut().scan_cache.clear()
    }

    /// Given a [`Matcher`], runs and caches a scan against `data` and yields the first
    /// match with the specified [`PatternId`].
    ///
    /// This function allows a caller to ignore the vectorized semantics of a single matcher
    /// potentially returning [`PatternMatch`]es with different pattern ids.
    fn cached_scan(
        &self,
        data: &'d [u8],
        pattern_id: PatternId,
    ) -> Result<Option<PatternMatch<'d>>, EvaluatorError> {
        let matcher_id = pattern_id.matcher_id();
        let cache_key = CacheKey::new(matcher_id.0 as usize, data);

        let scan_cache = &mut self.state.borrow_mut().scan_cache;
        match scan_cache.get_mut(&cache_key) {
            Some(matches_cache) => Ok(matches_cache.take_next(pattern_id)),
            None => {
                let mut matchers = self.evaluator.matchers.borrow_mut();
                let matcher = matchers
                    .get_mut(&matcher_id)
                    .expect("matcher for id should exist");

                let cursor = matcher.scan_data(data).map_err(EvaluatorError::Matcher)?;
                let existing = self.evaluator.bytes_scanned.take();
                self.evaluator.bytes_scanned.set(existing + data.len());
                // The scan succeeded and the cache key does not exist. Insert it and initialize a new vector.
                let matches_cache = scan_cache.entry(cache_key).or_default();

                let mut next: Option<PatternMatch> = None;
                for pattern_match in cursor {
                    // Potentially siphon off a single match and push the rest to the cache
                    if next.is_none() && pattern_match.pattern_id() == pattern_id {
                        next.replace(pattern_match);
                    } else {
                        matches_cache.push(pattern_match);
                    }
                }
                Ok(next)
            }
        }
    }

    /// Recursively evaluates a given [`EvalItem`], performing any scanning or caching necessary.
    fn eval(&self, item: EvalItem<'d>, depth: usize) -> Result<Evaluated<'d>, EvaluatorError> {
        match item.expr.as_ref() {
            Expression::IsMatch { source, pattern_id } => {
                let data_to_scan = match source {
                    MatchSource::Capture(name) => {
                        // If requested, find the named capture, or return an error if it doesn't exist.
                        self.state
                            .borrow_mut()
                            .captures_scratch
                            .get(name.as_str())
                            .copied()
                            .flatten()
                            .ok_or(EvaluatorError::UnknownCapture(name.to_string()))?
                    }
                    MatchSource::Prior => item.data_slice,
                };

                let pattern_match = self.cached_scan(data_to_scan, *pattern_id)?;

                Ok(match pattern_match {
                    Some(pm) if depth == 0 => Evaluated::TopLevelMatch(pm),
                    Some(_) => Evaluated::IntermediateMatch,
                    None => Evaluated::NoMatch,
                })
            }
            Expression::And(lhs, rhs) => {
                let left_child = EvalItem::from_parent(lhs, &item);
                let left_result = self.eval(left_child, depth + 1)?;

                if matches!(left_result, Evaluated::IntermediateMatch) {
                    let right_child = EvalItem::from_parent(rhs, &item);
                    self.eval(right_child, depth + 1)
                } else {
                    Ok(Evaluated::NoMatch)
                }
            }
            Expression::Or(lhs, rhs) => {
                let left_child = EvalItem::from_parent(lhs, &item);
                let left_result = self.eval(left_child, depth + 1)?;

                if matches!(left_result, Evaluated::IntermediateMatch) {
                    Ok(Evaluated::IntermediateMatch)
                } else {
                    let right_child = EvalItem::from_parent(rhs, &item);
                    self.eval(right_child, depth + 1)
                }
            }
            Expression::Not(expr) => {
                let expr = EvalItem::from_parent(expr, &item);
                let expr_result = self.eval(expr, depth + 1)?;
                Ok(match expr_result {
                    Evaluated::IntermediateMatch => Evaluated::NoMatch,
                    Evaluated::NoMatch => Evaluated::IntermediateMatch,
                    Evaluated::TopLevelMatch(_) => unreachable!("depth is > 0"),
                })
            }
        }
    }

    /// Caches the named captures from a [`PatternMatch`].
    fn cache_captures(&self, pattern_match: &PatternMatch<'d>) -> Result<(), EvaluatorError> {
        let captures_scratch = &mut self.state.borrow_mut().captures_scratch;
        for captures in pattern_match.captures() {
            if let (Some(name), Some(capture)) = captures {
                if let Some(value) = captures_scratch.get_mut(name) {
                    if value.replace(capture.as_bytes()).is_some() {
                        return Err(EvaluatorError::CaptureReassignment(name.into()));
                    }
                } else {
                    captures_scratch.insert(name.to_string(), Some(capture.as_bytes()));
                }
            }
        }
        Ok(())
    }
}

pub struct ScanIter<'a, 'd> {
    data: &'d [u8],
    pub rule_id: RuleId,
    evaluator: &'a RuleEvaluator,

    next_data_slice: &'d [u8],
    step_index: usize,

    s: &'a Scanner<'a, 'd>,
}

impl<'d> ScanIter<'_, 'd> {
    /// A shorthand getter for a [`Rule`]'s matcher [`Expression`] at a given index.
    ///
    /// # Panics
    /// Panics if a rule with `rule_id` is not present.
    fn get_expression(&self, idx: usize) -> Option<&Arc<Expression>> {
        self.evaluator
            .rules
            .get(&self.rule_id)
            .expect("rule should exist")
            .match_stages()
            .get(idx)
    }
}

impl FusedIterator for ScanIter<'_, '_> {}
impl<'d> Iterator for ScanIter<'_, 'd> {
    type Item = Result<EvalMatch<'d>, EvaluatorError>;

    fn next(&mut self) -> Option<Self::Item> {
        // The `candidate` loop cycles through each match candidate within a data source.
        'candidate: loop {
            let mut state = self.s.state.borrow_mut();
            state.captures_scratch.clear();
            state.p_match_scratch.clear();
            drop(state);

            self.step_index = 0;
            // Start by scanning the entire `data` to get all match candidates.
            self.next_data_slice = self.data;

            // Whether to break to `'candidate` upon `NoMatch` or not.
            let mut break_candidate = true;

            // Then, for each candidate, iterate through the rule's steps.
            while let Some(expr) = self.get_expression(self.step_index) {
                let eval_item = EvalItem::new(Arc::clone(expr), self.data, self.next_data_slice);

                let evaluated = match self.s.eval(eval_item, 0) {
                    Ok(val) => val,
                    Err(err) => return Some(Err(err)),
                };

                self.next_data_slice = match evaluated {
                    Evaluated::TopLevelMatch(pattern_match) => {
                        break_candidate = false;

                        if let Err(err) = self.s.cache_captures(&pattern_match) {
                            return Some(Err(err));
                        }
                        // In the case of a top level pattern match, we narrow down the scanned data so
                        // that all subsequent executions operate on this capture.
                        let next = pattern_match.entire().as_bytes();
                        let mut state = self.s.state.borrow_mut();
                        state.p_match_scratch.push(pattern_match);
                        next
                    }
                    Evaluated::IntermediateMatch => {
                        // In an IntermediateMatch, the data to scan is not narrowed, so all we do is pass
                        // the previous slice of data along.
                        // So, in this context, we return `next_data_slice` because it is equivalent to
                        // the slice we just evaluated.
                        self.next_data_slice
                    }
                    Evaluated::NoMatch => {
                        if break_candidate {
                            break 'candidate;
                        } else {
                            continue 'candidate;
                        }
                    }
                };
                self.step_index += 1;
            }

            // This must be a full rule-match
            let p_match_scratch = &mut self.s.state.borrow_mut().p_match_scratch;
            if !p_match_scratch.is_empty() {
                // We had a full rule match. Because of how successive matches can only be more narrow
                // than the previous, we know the first top-level match represents the entire span.
                let matched = p_match_scratch
                    .first()
                    .expect("length should have been checked")
                    .entire();
                let all_captures = p_match_scratch
                    .drain(..)
                    .map(|pm| {
                        let (_, _, captures) = pm.into_parts();
                        captures
                    })
                    .collect::<Vec<_>>();
                let eval_match = EvalMatch {
                    matched: Capture::new_from_data(self.data, matched.byte_span()),
                    all_captures,
                };

                return Some(Ok(eval_match));
            }
        }
        None
    }
}

/// `CacheKey` is used to indicate that a given sequence of bytes has been scanned by a specific [`Matcher`].
///
/// In order for two `CacheKey` to be equal, their `data` must point to the same exact memory addresses.
/// The actual data is not a part of the hash, and so two different byte slices that are identical
/// in contents will have different hashes.
//
// This key was selected because a [`Matcher`] can be vectorized, meaning that a single scan of the data
// can generate matches for multiple patterns (and by extension, multiple rules). Multiple rules will
// thus commonly share a reference to the same Matcher. In order to scan a data source against
// every single rule, at some point, we need to iterate through each rule to verify that its
// match predicates have been evaluated. In a non-vectorized scenario, if we had 1000 rules, it would
// mean that for each data source, we would have to scan the bytes 1000 times to check the data
// against every single rule.
//
// In contrast, with a vectorized `Matcher` like `Hyperscan`, those 1000 rules are checked in 1 single scan.
//
// However, we'll still need to iterate through every rule to ensure the match predicates
// have been evaluated. This `CacheKey` allows that to happen very inexpensively: the first scan will
// cache this key, and the other 999 iterations will see a cache hit, preventing redundant scanning.
//
// Because a frequent `CacheKey` check will be to see if an entire file has been scanned by a `Matcher`,
// the hash function has been optimized to be an `O(1)` operation, as the actual bytes
// themselves are not fed into the hasher. Instead, we use the pointers to the underlying data.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct CacheKey {
    /// An arbitrary, but unique key disambiguating a [`Matcher`] from another `Matcher`.
    matcher_key: usize,
    /// The two raw pointers spanning the slice passed in as input data.
    data: std::ops::Range<*const u8>,
}

impl CacheKey {
    /// Constructs a new `CacheKey` using the provided `matcher_key` and the raw pointers from `data`.
    pub fn new(matcher_key: usize, data: &[u8]) -> Self {
        Self {
            matcher_key,
            data: data.as_ptr_range(),
        }
    }
}

/// An [`EvalMatch`] represents a slice that has matched every predicate in a given rule.
#[derive(Clone)]
pub struct EvalMatch<'d> {
    pub matched: Capture<'d>,
    /// Because a rule evaluation might have multiple top-level matches that create
    /// captures, but we only surface the first top-level match as `matched`, we need
    /// to collect all the captures so that they can be accessed by a validator.
    ///
    /// A vector of [`Captures`] is used instead of merging the [`Captures`] structs together
    /// for simplicity's sake.
    pub all_captures: Vec<Captures<'d>>,
}

impl Debug for EvalMatch<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EvalMatch")
            .field("matched", &BStr::new(self.matched.as_bytes()))
            .field("captures", &self.all_captures)
            .finish_non_exhaustive()
    }
}

#[rustfmt::skip]
#[cfg(test)]
mod tests {
    use crate::matcher::hyperscan::{Hyperscan, Pattern, PatternSet};
    use crate::matcher::hyperscan::pattern_set::PatternSetBuilder;
    use crate::matcher::{Matcher, MatcherId, PatternId};
    use crate::rule::MatchSource;
    use crate::rule::{Expression, Rule, RuleId};
    use crate::rule_evaluator::{CacheKey, EvalMatch, EvaluatorError, RuleEvaluator};
    use std::collections::HashMap;
    use std::mem;
    use std::rc::Rc;
    use std::sync::Arc;

    /// A mirror of [`Expression`] to provide ergonomic test-case construction
    enum Source {
        Prior(&'static str),
        Capture(&'static str, &'static str),
        And(Box<Source>, Box<Source>),
        Or(Box<Source>, Box<Source>),
        Not(Box<Source>),
    }

    /// Crawls a [`Source`] tree and reconstructs an equivalent [`Expression`] tree. Each patter
    /// passed in is compiled into a [`Hyperscan`] matcher.
    fn build_tree(source: &Source, psb: &mut PatternSetBuilder) -> Arc<Expression> {
        match source {
            Source::Prior(expr) => {
                let p_id = psb.add_pattern(vectorscan::Pattern::new(*expr).try_build().unwrap());
                Arc::new(Expression::IsMatch {
                    source: MatchSource::Prior,
                    pattern_id: p_id,
                })
            }
            Source::Capture(name, expr) => {
                let p_id = psb.add_pattern(vectorscan::Pattern::new(*expr).try_build().unwrap());
                Arc::new(Expression::IsMatch {
                    source: MatchSource::Capture(name.to_string()),
                    pattern_id: p_id,
                })
            }
            Source::And(lhs, rhs) => {
                Arc::new(Expression::And(build_tree(lhs, psb), build_tree(rhs, psb)))
            }
            Source::Or(lhs, rhs) => {
                Arc::new(Expression::Or(build_tree(lhs, psb), build_tree(rhs, psb)))
            }
            Source::Not(expr) => {
                Arc::new(Expression::Not(build_tree(expr, psb)))
            }
        }
    }

    #[allow(clippy::vec_box)]
    fn build<'d>(rules: Vec<(RuleId, Vec<Box<Source>>)>) -> RuleEvaluator {
        // Convert the patterns into an [`Expression`], and generate the matcher, as well as the pattern-ids.
        let m_id = MatcherId(0);
        let mut psb = PatternSetBuilder::new(m_id);

        let rules = rules
            .iter()
            .map(|rule| {
                let expressions = rule
                    .1
                    .iter()
                    .map(|pattern| Arc::try_unwrap(build_tree(pattern, &mut psb)).unwrap())
                    .collect::<Vec<_>>();
                Arc::new(Rule::new(rule.0.clone(), vec![], expressions, "validator-1".into()))
            })
            .collect::<Vec<_>>();

        let hs = Hyperscan::new(psb.try_compile().unwrap());
        RuleEvaluator::new(vec![Matcher::Hyperscan(hs)], rules.as_slice())
    }

    fn match_prior(expr: &'static str) -> Box<Source> { Box::new(Source::Prior(expr)) }
    fn match_cap(name: &'static str, expr: &'static str) -> Box<Source> { Box::new(Source::Capture(name, expr)) }
    fn and(lhs: Box<Source>, rhs: Box<Source>) -> Box<Source> { Box::new(Source::And(lhs, rhs)) }
    fn or(lhs: Box<Source>, rhs: Box<Source>) -> Box<Source> { Box::new(Source::Or(lhs, rhs)) }
    fn not(src: Box<Source>) -> Box<Source> { Box::new(Source::Not(src)) }

    fn get_text(eval_match: Option<Result<EvalMatch, EvaluatorError>>) -> &str {
        std::str::from_utf8(eval_match.unwrap().unwrap().matched.as_bytes()).unwrap()
    }

    /// The cache remains in place, but is drained when pattern matches are retrieved.
    #[test]
    fn scan_cache_drained_in_place() {
        let rule_id: RuleId = "rule-1".into();
        let evaluator = build(vec![(rule_id.clone(), vec![match_prior("[a-z]+")])]);
        let source = "---abc---abc---".as_bytes();
        let mut scanner = evaluator.scan(source);
        assert_eq!(scanner.rule(&rule_id).collect::<Vec<_>>().len(), 2);
        assert_eq!(evaluator.bytes_scanned.get(), 15);

        assert_eq!(scanner.rule(&rule_id).collect::<Vec<_>>().len(), 0);
        assert_eq!(evaluator.bytes_scanned.get(), 15);

        scanner.clear_cache();
        assert_eq!(scanner.rule(&rule_id).collect::<Vec<_>>().len(), 2);
        assert_eq!(evaluator.bytes_scanned.get(), 30);
    }

    /// Cache prevents rescans of the same data, even across different rules
    #[test]
    fn scan_cache_prevents_rescan() {
        let rule_1: RuleId = "rule-1".into();
        let rule_2: RuleId = "rule-2".into();
        let evaluator = build(vec![
            (rule_1.clone(), vec![match_prior("[a-z]{3}")]),
            (rule_2.clone(), vec![match_prior("[0-9]{3}")]),
        ]);
        let source = "---abc---123---def---".as_bytes();
        let scanner = evaluator.scan(source);

        let iter = scanner.rule(&rule_1);
        assert_eq!(iter.collect::<Vec<_>>().len(), 2);
        assert_eq!(evaluator.bytes_scanned.get(), 21);

        let iter = scanner.rule(&rule_2);
        assert_eq!(iter.collect::<Vec<_>>().len(), 1);
        assert_eq!(evaluator.bytes_scanned.get(), 21);
    }

    /// Sequential match stages are re-scanned individually.
    #[test]
    fn sequential_match_byte_scan() {
        let rule_1: RuleId = "rule-1".into();
        let evaluator = build(vec![
            (rule_1.clone(), vec![
                match_prior("[a-z]{12}"),
                match_prior("[a-z]{6}"),
                match_prior("[a-z]{3}"),
                match_prior("abc"),
            ])
        ]);
        let source = "abcdefghijklmno".as_bytes();
        let scanner = evaluator.scan(source);
        let mut iter = scanner.rule(&rule_1);
        assert_eq!(iter.evaluator.bytes_scanned.get(), 0);
        let _ = iter.next();
        assert_eq!(iter.evaluator.bytes_scanned.get(), 15 + 12 + 6 + 3);
    }

    #[test]
    fn boolean_logic() {
        let rule_1: RuleId = "rule-1".into();
        let rule_2: RuleId = "rule-2".into();
        let evaluator = build(vec![
            (rule_1.clone(), vec![
                match_prior("[0-9]{6}"),
                not(match_prior("0{6}|1{6}|2{6}|3{6}|4{6}|5{6}|6{6}|7{6}|8{6}|9{6}")),
            ]),
            (rule_2.clone(), vec![
                match_prior("0x([a-fA-F0-9]{8})"),
                and(
                    or(match_prior("A"), match_prior("B")),
                    and(not(match_prior("C")), match_prior("D")),
                )
            ]),
        ]);
        let source = "123456---111111---222222---987654---123456".as_bytes();
        let scanner = evaluator.scan(source);
        let mut iter = scanner.rule(&rule_1);
        assert_eq!(get_text(iter.next()), "123456");
        assert_eq!(get_text(iter.next()), "987654");
        assert_eq!(get_text(iter.next()), "123456");
        assert!(iter.next().is_none());

        let source = "0xAABBCCDD---0xAABB11DD---0xADDD2222---0xDDDD2222".as_bytes();
        let scanner = evaluator.scan(source);
        let mut iter = scanner.rule(&rule_2);
        assert_eq!(get_text(iter.next()), "0xAABB11DD");
        assert_eq!(get_text(iter.next()), "0xADDD2222");
        assert!(iter.next().is_none());
    }

    /// Tests that the iterator _can't_ be consistently used to have intermediate matches as the first
    /// expression because they will get consumed by the first top-level capture.
    ///
    /// (This should be expressed as a [`RuleCondition`](crate::rule::RuleCondition))
    #[test]
    fn intermediate_match_before_top_level() {
        let rule_1: RuleId = "rule-1".into();
        let evaluator = build(vec![
            (rule_1.clone(), vec![
                and(match_prior("key"), match_prior("word")),
                match_prior("[0-9]{6}"),
            ])
        ]);
        let source = "key---111111---222222---word---".as_bytes();
        let scanner = evaluator.scan(source);
        let mut iter = scanner.rule(&rule_1);
        assert_eq!(get_text(iter.next()), "111111");
        // This will _not_ be Some("222222"), as might have been intended.
        assert!(iter.next().is_none());

        // However, if there are two "key" and two "word", then there is a second match,
        // because the second "key" and "word" are consumed for the second number.
        let source = "key---111111---222222---word---keyword".as_bytes();
        let scanner = evaluator.scan(source);
        let mut iter = scanner.rule(&rule_1);
        assert_eq!(get_text(iter.next()), "111111");
        assert_eq!(get_text(iter.next()), "222222");
    }

    #[test]
    fn boolean_logic_capture_name() {
        let rule_1: RuleId = "rule-1".into();
        let evaluator = build(vec![
            (rule_1.clone(), vec![
                match_prior("(?<token>(?<cap_a>[[:lower:]]{3})_(?<cap_b>[[:alpha:]]{3}))"),
                or(
                    match_cap("cap_a", "abc"),
                    match_cap("cap_b", "XYZ")
                )
            ]),
        ]);
        let source = "---abc_DEF---xyz---def_ABC---xyz_XYZ---".as_bytes();
        let scanner = evaluator.scan(source);
        let mut iter = scanner.rule(&rule_1);
        assert_eq!(get_text(iter.next()), "abc_DEF");
        assert_eq!(get_text(iter.next()), "xyz_XYZ");
    }

    #[test]
    fn error_capture_reassignment() {
        let rule_1: RuleId = "rule-1".into();
        let evaluator = build(vec![
            (rule_1.clone(), vec![
                match_prior("(?<cap_a>[a-zA-Z]{3})"),
                match_prior("(?<cap_a>[a-z]{3})"),
            ])
        ]);
        let source = "---abc---".as_bytes();
        let scanner = evaluator.scan(source);
        let mut iter = scanner.rule(&rule_1);
        assert!(matches!(
            iter.next().unwrap().unwrap_err(),
            EvaluatorError::CaptureReassignment(name) if name == "cap_a".to_string()
        ));
    }

    #[test]
    fn error_unknown_capture() {
        let rule_1: RuleId = "rule-1".into();
        let evaluator = build(vec![
            (rule_1.clone(), vec![
                match_prior("(?<cap_a>[a-zA-Z]{3})"),
                match_cap("cap_b", ".+"),
            ])
        ]);
        let source = "---abc---".as_bytes();
        let scanner = evaluator.scan(source);
        let mut iter = scanner.rule(&rule_1);
        assert!(matches!(
            iter.next().unwrap().unwrap_err(),
            EvaluatorError::UnknownCapture(name) if name == "cap_b".to_string()
        ));
    }

    /// Anchors operate on the sequentially-narrowed slices
    #[test]
    fn sequential_regex_anchors() {
        let rule_1: RuleId = "rule-1".into();
        let rule_2: RuleId = "rule-2".into();
        let rule_3: RuleId = "rule-3".into();
        let evaluator = build(vec![
            (rule_1.clone(), vec![
                match_prior("[a-z]{6,}"),
                match_prior("^(abcdef)$")
            ]),
            (rule_2.clone(), vec![
                match_prior("[a-z]{6,}"),
                match_prior("^(abc)")
            ]),
            (rule_3.clone(), vec![
                match_prior("[a-z]{6,}"),
                match_prior("(def)$")
            ]),
        ]);
        let source = "---abcdef---defabc---abcdefghi---".as_bytes();
        let scanner = evaluator.scan(source);
        let mut iter = scanner.rule(&rule_1);
        assert_eq!(get_text(iter.next()), "abcdef");
        assert!(iter.next().is_none());

        let scanner = evaluator.scan(source);
        let mut iter = scanner.rule(&rule_2);
        assert_eq!(get_text(iter.next()), "abcdef");
        assert_eq!(get_text(iter.next()), "abcdefghi");
        assert!(iter.next().is_none());

        let scanner = evaluator.scan(source);
        let mut iter = scanner.rule(&rule_3);
        assert_eq!(get_text(iter.next()), "abcdef");
        assert!(iter.next().is_none());
    }
}
