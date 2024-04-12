// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::checker::PatternChecker;
use crate::matcher::{Matcher, MatcherError, MatcherId, PatternId, PatternMatch};
use crate::rule::{Rule, RuleId};
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
            state: RefCell::new(ScannerState(HashMap::new())),
            evaluator: self,
            data,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EvaluatorError {
    #[error("capture with name `{0}` does not exist")]
    UnknownCapture(String),
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

/// A cache to store a vector of [`PatternMatch`] from a single matcher's scan of an input data.
/// This cache allows matchers to perform vectorized scans in a way that is abstracted
/// away from the caller.
#[derive(Debug, Default, Clone)]
struct ScannerState<'d>(HashMap<CacheKey, MatchesCache<'d>>);

impl<'d> ScannerState<'d> {
    /// Returns a mutable reference to the [`MatchesCache`] associated with the provided cache key.
    ///
    /// # Panics
    /// Panics if the cache key does not exist in the hash map.
    pub fn get_mut(&mut self, cache_key: &CacheKey) -> &mut MatchesCache<'d> {
        self.0
            .get_mut(cache_key)
            .expect("caller should have passed in cache key that exists")
    }
}

pub struct Scanner<'a, 'd> {
    state: RefCell<ScannerState<'d>>,
    evaluator: &'a RuleEvaluator,
    data: &'d [u8],
}

impl<'a, 'd> Scanner<'a, 'd> {
    /// Performs a scan using the [`Matcher`] associated with the specified rule and creates an iterator
    /// over the results.
    ///
    /// NOTE: Until the cache is cleared with [`Self::clear_cache`], each call to `next()` on the iterator
    /// permanently advances the `Scanner` state for the given rule. Thus, if a duplicate call (with the same
    /// rule) is made, the iterator returned will only yield previously un-yielded values.
    pub fn rule(&'a self, rule_id: &RuleId) -> Result<ScanIter<'a, 'd>, EvaluatorError> {
        let rule = self
            .evaluator
            .rules
            .get(rule_id)
            .expect("rule should exist");

        let checker = rule.match_checks();
        let pattern_id = rule.pattern_id();
        let cache_key = self.ensure_scanned(self.data, rule.pattern_id())?;

        Ok(ScanIter {
            data: self.data,
            cache_key,
            pattern_id,
            pm_checkers: checker,
            state: &self.state,
        })
    }

    /// Clears the entire underlying [`PatternMatch`] cache, removing all keys and values.
    pub(crate) fn clear_cache(&mut self) {
        self.state.get_mut().0.clear()
    }

    /// Ensures the passed in data has been completed scanned by the [`Matcher`] associated with
    /// the passed in pattern. Returns the [`CacheKey`] calculated, so that the caller can
    /// look up the associated [`MatchesCache`].
    fn ensure_scanned(
        &self,
        data: &'d [u8],
        pattern_id: PatternId,
    ) -> Result<CacheKey, EvaluatorError> {
        let matcher_id = pattern_id.matcher_id();
        let cache_key = CacheKey::new(matcher_id.0 as usize, data);

        let scan_cache = &mut self.state.borrow_mut().0;
        match scan_cache.get_mut(&cache_key) {
            Some(_) => {}
            None => {
                let mut matchers = self.evaluator.matchers.borrow_mut();
                let matcher = matchers
                    .get_mut(&matcher_id)
                    .expect("matcher for id should exist");

                let cursor = matcher.scan_data(data).map_err(EvaluatorError::Matcher)?;
                let existing = self.evaluator.bytes_scanned.take();
                self.evaluator.bytes_scanned.set(existing + data.len());
                // The scan succeeded and the cache key does not exist. Insert it and initialize a new vector.
                let matches_cache = scan_cache.entry(cache_key.clone()).or_default();

                for pattern_match in cursor {
                    matches_cache.push(pattern_match);
                }
            }
        }
        Ok(cache_key)
    }
}

/// An iterator over the (mutable) state of a [`Scanner`] for a specific [`PatternId`].
pub struct ScanIter<'a, 'd> {
    data: &'d [u8],
    cache_key: CacheKey,
    pattern_id: PatternId,
    pm_checkers: &'a [Box<dyn PatternChecker>],
    state: &'a RefCell<ScannerState<'d>>,
}

impl FusedIterator for ScanIter<'_, '_> {}
impl<'a, 'd> Iterator for ScanIter<'a, 'd> {
    type Item = CheckedMatch<'d>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut state = self.state.borrow_mut();
        let matches_cache = state.get_mut(&self.cache_key);

        'p_match: while let Some(pattern_match) = matches_cache.take_next(self.pattern_id) {
            for pm_checker in self.pm_checkers {
                if !pm_checker.check(&pattern_match) {
                    continue 'p_match;
                }
            }
            return Some(CheckedMatch(pattern_match));
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

/// A [`PatternMatch`] that has passed a [`Checker`] and will be sent to a validator.
#[derive(Clone, Eq, PartialEq)]
pub struct CheckedMatch<'d>(pub PatternMatch<'d>);

impl Debug for CheckedMatch<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CheckedMatch")
            .field("pattern_id", &self.0.pattern_id())
            .field("full_data", &self.0.full_data().as_ptr_range())
            .field("captures", &self.0.captures())
            .finish()
    }
}

#[rustfmt::skip]
#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use crate::{Matcher, PatternChecker, Rule};
    use crate::checker::Regex;
    use crate::matcher::hyperscan::Hyperscan;
    use crate::matcher::hyperscan::pattern_set::PatternSetBuilder;
    use crate::matcher::MatcherId;
    use crate::rule::{RuleId, TargetedChecker};
    use crate::rule_evaluator::{CheckedMatch, RuleEvaluator};

    fn build(rules: Vec<(RuleId, &str, Vec<Box<dyn PatternChecker>>)>) -> RuleEvaluator {
        let m_id = MatcherId(0);
        let mut psb = PatternSetBuilder::new(m_id);

        let rules = rules
            .into_iter()
            .map(|(rule, expression, checks)| {
                let pattern = vectorscan::Pattern::new(expression).try_build().unwrap();
                let pattern_id = psb.add_pattern(pattern);
                Arc::new(Rule::new(rule.clone(), pattern_id, "validator-1".into(), vec![], checks))
            })
            .collect::<Vec<_>>();

        let hs = Hyperscan::new(psb.try_compile().unwrap());
        RuleEvaluator::new(vec![Matcher::Hyperscan(hs)], rules.as_slice())
    }

    /// A shorthand to allow for ergonomic test assertions
    fn as_strs<'a>(checked_matches: &'a [CheckedMatch]) -> Vec<&'a str> {
        checked_matches
            .iter()
            .map(|c| c.0.entire().as_str().unwrap())
            .collect::<Vec<_>>()
    }

    /// The cache remains in place, but is drained when pattern matches are retrieved.
    #[test]
    fn scan_cache_drained_in_place() {
        let rule_id: RuleId = "rule-1".into();
        let evaluator = build(vec![(rule_id.clone(), "[a-z]+", vec![])]);
        let mut scanner = evaluator.scan("---abc---abc---".as_bytes());
        assert_eq!(scanner.rule(&rule_id).unwrap().collect::<Vec<_>>().len(), 2);
        assert_eq!(evaluator.bytes_scanned.get(), 15);

        assert_eq!(scanner.rule(&rule_id).unwrap().collect::<Vec<_>>().len(), 0);
        assert_eq!(evaluator.bytes_scanned.get(), 15);

        scanner.clear_cache();
        assert_eq!(scanner.rule(&rule_id).unwrap().collect::<Vec<_>>().len(), 2);
        assert_eq!(evaluator.bytes_scanned.get(), 30);
    }

    /// Cache prevents rescans of the same data, even across different rules
    #[test]
    fn scan_cache_prevents_rescan() {
        let rule_1: RuleId = "rule-1".into();
        let rule_2: RuleId = "rule-2".into();
        let evaluator = build(vec![
            (rule_1.clone(), "[a-z]{3}", vec![]),
            (rule_2.clone(), "[0-9]{3}", vec![]),
        ]);
        let scanner = evaluator.scan("---abc---123---def---".as_bytes());

        let iter = scanner.rule(&rule_1).unwrap();
        assert_eq!(iter.collect::<Vec<_>>().len(), 2);
        assert_eq!(evaluator.bytes_scanned.get(), 21);

        let iter = scanner.rule(&rule_2).unwrap();
        assert_eq!(iter.collect::<Vec<_>>().len(), 1);
        assert_eq!(evaluator.bytes_scanned.get(), 21);
    }

    /// A sequential list of checks are used to qualify or disqualify matches.
    #[test]
    fn eval_matcher_candidate_checks() {
        let rule_1: RuleId = "rule-1".into();
        let rule_2: RuleId = "rule-2".into();
        // A `PatternChecker` that asserts the candidate contains "abc" somewhere
        let regex1 = TargetedChecker::candidate(Regex::try_new("abc").unwrap());
        // A `PatternChecker` that asserts the candidate ends with a number.
        let regex2 = TargetedChecker::candidate(Regex::try_new(r#"\d$"#).unwrap());

        let evaluator = build(vec![
            (rule_1.clone(), "[[:alnum:]-]{15}", vec![]),
            (rule_2.clone(), "[[:alnum:]-]{15}", vec![regex1, regex2]),
        ]);
        let data =
            "\
            abc---def---ghi     fails: [regex2]                 passes: [regex1]
            def---abc---111     fails: []                       passes: [regex1, regex2]
            111---222---333     fails: [regex1]                 passes: [regex2]
            def---ghi---jkl     fails: [regex1, regex2]         passes: []
            abc---abc---222     fails: []                       passes: [regex1, regex2]
            "
                .as_bytes()
        ;
        let scanner = evaluator.scan(data);

        let rule1_matches = scanner.rule(&rule_1).unwrap().collect::<Vec<_>>();
        assert_eq!(
            as_strs(&rule1_matches),
            vec![
                "abc---def---ghi",
                "def---abc---111",
                "111---222---333",
                "def---ghi---jkl",
                "abc---abc---222"
            ]
        );

        let rule2_matches = scanner.rule(&rule_2).unwrap().collect::<Vec<_>>();
        assert_eq!(
            as_strs(&rule2_matches),
            vec![
                "def---abc---111",
                "abc---abc---222",
            ]
        );
    }
}
