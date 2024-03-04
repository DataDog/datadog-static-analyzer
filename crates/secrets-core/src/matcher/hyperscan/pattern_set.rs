// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::matcher::hyperscan::pattern::{InnerRegex, Pattern, PatternKind, PatternWidth};
use std::collections::HashMap;
use std::sync::Arc;
use vectorscan::database::BlockDatabase;
use vectorscan::error::Error;
use vectorscan::scan::PatternId;

/// A set of [`NamedPattern`]s, where each pattern has a unique string id.
///
/// Internally, the set assigns an incrementing [`PatternId`] to each [`vectorscan::Pattern`] in
/// the order it was inserted. If the pattern had an existing [`PatternId`], it will be reassigned.
///
/// The complete set of [`NamedPattern`]s is guaranteed to have internal ids contiguous from 0 to n.
#[derive(Debug)]
pub(crate) struct PatternSet {
    database: Arc<BlockDatabase>,
    patterns: Vec<NamedPattern>,
}

impl PatternSet {
    /// Returns a builder to construct a [`PatternSet`].
    #[allow(clippy::new_ret_no_self)]
    pub fn new() -> PatternSetBuilder {
        PatternSetBuilder::new()
    }

    /// Returns a reference to a [`NamedPattern`] with the given id.
    pub fn get(&self, id: PatternId) -> Option<&NamedPattern> {
        self.patterns.get(id.0 as usize)
    }

    /// Returns a mutable reference to a [`NamedPattern`] with the given id.
    pub fn get_mut(&mut self, id: PatternId) -> Option<&mut NamedPattern> {
        self.patterns.get_mut(id.0 as usize)
    }

    /// Returns the number of patterns in the set.
    pub fn len(&self) -> usize {
        self.patterns.len()
    }

    /// Returns a reference to the underlying Hyperscan database.
    pub fn database(&self) -> &BlockDatabase {
        &self.database
    }

    /// Consumes the [`PatternSet`], returning its parts.
    pub fn into_parts(self) -> (Arc<BlockDatabase>, Vec<NamedPattern>) {
        (self.database, self.patterns)
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum PatternSetError {
    /// Returns the duplicated names, as well as the conflicting Patterns
    #[error("pattern id `{0}` must be unique")]
    DuplicateNames(String, [vectorscan::Pattern; 2]),
    /// An error constructing a `pcre2` Regex
    #[error(transparent)]
    Regex(#[from] pcre2::Error),
    /// An error from the `vectorscan` library
    #[error("library error: {0}")]
    Library(#[from] Error),
}

/// A [`Pattern`] with a human-friendly string id.
#[derive(Debug, Clone)]
pub struct NamedPattern(Arc<str>, Pattern);

impl NamedPattern {
    pub fn new(name: Arc<str>, pattern: Pattern) -> Self {
        Self(name, pattern)
    }

    pub fn to_name_arc(&self) -> Arc<str> {
        Arc::clone(&self.0)
    }

    pub fn name(&self) -> &str {
        &self.0
    }

    pub fn inner(&self) -> &Pattern {
        &self.1
    }

    pub fn inner_mut(&mut self) -> &mut Pattern {
        &mut self.1
    }
}

#[derive(Debug, Default, Clone)]
pub(crate) struct PatternSetBuilder(Vec<(Arc<str>, vectorscan::Pattern)>);

impl PatternSetBuilder {
    /// Creates a new builder for a [`PatternSet`].
    pub fn new() -> Self {
        Self(Vec::new())
    }

    /// Adds a [`Pattern`] to the set.
    pub fn pattern(mut self, pat: (Arc<str>, vectorscan::Pattern)) -> Self {
        let next_id = self.0.len() as u32;
        let pat = (pat.0, pat.1.clone_with_id(next_id));
        self.0.push(pat);
        self
    }

    /// Attempts to compile all the patterns, returning an [`PatternSet`] if successful
    pub fn try_compile(self) -> Result<PatternSet, PatternSetError> {
        // Because of how patterns are added to the builder, they are guaranteed to have
        // unique, n+1 numeric id.
        //
        // However, because the name is provided by the user, we need to ensure each is unique.
        let mut hs_patterns = HashMap::with_capacity(self.0.len());
        for ((name, pattern)) in self.0.iter() {
            if let Some(existing) = hs_patterns.insert(Arc::clone(name), pattern) {
                return Err(PatternSetError::DuplicateNames(
                    name.to_string(),
                    [existing.clone(), pattern.clone()],
                ));
            }
        }

        let database = BlockDatabase::try_new(self.0.iter().map(|(_, pat)| pat))?;
        // Hyperscan supports libpcre(2) syntax, even though it has different semantics.
        // https://intel.github.io/hyperscan/dev-reference/compilation.html#semantics
        //
        // This means that because database compilation succeeded, all the regex patterns
        // contain valid pcre2 syntax, so we augment the Pattern with a backing regex to provide
        // captures and true start-of-match detection.
        let patterns: Result<Vec<NamedPattern>, PatternSetError> = self
            .0
            .into_iter()
            .map(|(name, hs_pattern)| {
                // NOTE: An error here should never occur (see above regarding successful Hyperscan compilation)
                let pattern: Pattern = hs_pattern.try_into().map_err(PatternSetError::Regex)?;
                Ok(NamedPattern(name, pattern))
            })
            .collect();
        let patterns = patterns?;

        Ok(PatternSet {
            database: Arc::new(database),
            patterns,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{PatternSet, PatternSetBuilder, PatternSetError};
    use std::sync::Arc;
    use vectorscan::Pattern as HsPattern;

    /// The [`PatternSetBuilder`] should assign [`vectorscan::scan::PatternId`] ids from 0 to n, regardless
    /// of whether the incoming pattern had an id already assigned.
    #[rustfmt::skip]
    #[test]
    fn builder_incrementing_hs_pattern_ids() {
        // Patterns without default ids (0)
        let pat1 = HsPattern::new("abc?").try_build().unwrap();
        let pat2 = HsPattern::new("def?").try_build().unwrap();
        let pat3 = HsPattern::new("ghi?").try_build().unwrap();
        assert_eq!((pat1.id(), pat2.id(), pat3.id()), (0, 0, 0));

        // Patterns with existing unique ids
        let pat4 = HsPattern::new("jkl?").id(123).try_build().unwrap();
        let pat5 = HsPattern::new("mno?").id(456).try_build().unwrap();
        let pat6 = HsPattern::new("pqr?").id(789).try_build().unwrap();

        // Patterns with existing non-unique ids
        let pat7 = HsPattern::new("jkl?").id(123).try_build().unwrap();
        let pat8 = HsPattern::new("mno?").id(456).try_build().unwrap();
        let pat9 = HsPattern::new("pqr?").id(456).try_build().unwrap();

        for (pat_a, pat_b, pat_c) in [(pat1, pat2, pat3), (pat4, pat5, pat6), (pat7, pat8, pat9)] {
            let set = PatternSet::new().pattern(("a1".into(), pat_a)).pattern(("b2".into(), pat_b)).pattern(("c3".into(), pat_c));
            assert_eq!(
                set.try_compile().unwrap().patterns.iter().map(|np| np.inner().hs().id()).collect::<Vec<_>>(),
                vec![0, 1, 2]
            );
        }
    }

    /// The PatternSet should fail to compile if there are duplicate names.
    #[test]
    fn builder_unique_names() {
        let pat1 = HsPattern::new("abc?").try_build().unwrap();
        let pat2 = HsPattern::new("def?").try_build().unwrap();
        let pat3 = HsPattern::new("ghi?").try_build().unwrap();
        let dup_name = "name-2";
        let set = PatternSet::new()
            .pattern(("name-1".into(), pat1))
            .pattern((dup_name.into(), pat2))
            .pattern((dup_name.into(), pat3));
        let duplicate_name = dup_name.to_string();
        assert!(set
            .try_compile()
            .is_err_and(|err| matches!(err, PatternSetError::DuplicateNames(duplicate_name, _))));

        let pat1 = HsPattern::new("abc?").try_build().unwrap();
        let pat2 = HsPattern::new("def?").try_build().unwrap();
        let set = PatternSet::new()
            .pattern(("name-1".into(), pat1))
            .pattern(("name-2".into(), pat2));
        assert!(set.try_compile().is_ok_and(|es| es.len() == 2));
    }

    /// The PatternSet doesn't require expressions to be unique.
    #[test]
    fn allow_duplicate_expressions() {
        // As long as the names are different, patterns don't have to be unique
        let expression = "abc?";
        let pat1 = HsPattern::new(expression).try_build().unwrap();
        let pat2 = HsPattern::new(expression).try_build().unwrap();
        let set = PatternSet::new()
            .pattern(("name-1".into(), pat1))
            .pattern(("name-2".into(), pat2));
        assert!(set.try_compile().is_ok_and(|es| es.len() == 2));
    }
}
