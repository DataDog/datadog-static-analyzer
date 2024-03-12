// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::matcher::hyperscan::Pattern;
use crate::matcher::{MatcherId, PatternId};
use std::sync::Arc;
use vectorscan::database::BlockDatabase;

/// A set of [`PatternWithId`] with a compiled [`BlockDatabase`].
///
/// Internally, the set assigns an incrementing [`PatternId`] to each [`vectorscan::Pattern`] in
/// the order it was inserted, from 0 to n. The original [`vectorscan::Pattern::id`] is ignored.
#[derive(Debug, Clone)]
pub struct PatternSet {
    pub matcher_id: MatcherId,
    database: Arc<BlockDatabase>,
    patterns: Vec<PatternWithId>,
}

impl PatternSet {
    /// Returns a builder to construct a [`PatternSet`].
    #[allow(clippy::new_ret_no_self)]
    pub fn new(matcher_id: MatcherId) -> PatternSetBuilder {
        PatternSetBuilder::new(matcher_id)
    }

    /// Returns a reference to a [`PatternWithId`] with the given Hyperscan id.
    pub fn get(&self, id: vectorscan::scan::PatternId) -> Option<&PatternWithId> {
        self.patterns.get(id.0 as usize)
    }

    /// Returns a mutable reference to a [`PatternWithId`] with the given Hyperscan id.
    pub fn get_mut(&mut self, id: vectorscan::scan::PatternId) -> Option<&mut PatternWithId> {
        self.patterns.get_mut(id.0 as usize)
    }

    /// Returns the number of patterns in the set.
    pub fn len(&self) -> usize {
        self.patterns.len()
    }

    /// Returns `true` if the set contains no patterns.
    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// Returns a reference to the underlying Hyperscan database.
    pub fn database(&self) -> &BlockDatabase {
        &self.database
    }

    /// Consumes the [`PatternSet`], returning its parts.
    pub fn into_parts(self) -> (Arc<BlockDatabase>, Vec<PatternWithId>) {
        (self.database, self.patterns)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PatternSetError {
    /// An error constructing a `pcre2` Regex
    #[error(transparent)]
    Regex(#[from] pcre2::Error),
    /// An error from the `vectorscan` library
    #[error("library error: {0}")]
    Library(#[from] vectorscan::Error),
}

/// A [`Pattern`] with an associated [`PatternId`].
#[derive(Debug, Clone)]
pub struct PatternWithId {
    pub id: PatternId,
    pattern: Pattern,
}

impl PatternWithId {
    pub fn new(id: PatternId, pattern: Pattern) -> Self {
        Self { id, pattern }
    }

    pub fn inner(&self) -> &Pattern {
        &self.pattern
    }

    pub fn inner_mut(&mut self) -> &mut Pattern {
        &mut self.pattern
    }
}

#[derive(Debug, Default, Clone)]
pub struct PatternSetBuilder {
    pub matcher_id: MatcherId,
    patterns: Vec<(PatternId, vectorscan::Pattern)>,
}

impl PatternSetBuilder {
    /// Creates a new builder for a [`PatternSet`].
    pub fn new(matcher_id: MatcherId) -> Self {
        Self {
            matcher_id,
            patterns: Vec::new(),
        }
    }

    /// Adds a [`vectorscan::Pattern`] to the set, but doesn't return the generated [`PatternId`].
    pub fn pattern(mut self, pattern: vectorscan::Pattern) -> Self {
        let _ = self.add_pattern(pattern);
        self
    }

    /// Adds a [`vectorscan::Pattern`] to the set, returning the generated [`PatternId`].
    pub fn add_pattern(&mut self, pattern: vectorscan::Pattern) -> PatternId {
        let pattern_id = self.patterns.last().map(|(pid, _)| pid.0 + 1).unwrap_or(0);
        let pattern_id = PatternId(pattern_id, self.matcher_id);

        // Note: The hs_id used happens to be the same as pattern_id (though it's not required)
        let next_hs_id = self.patterns.len() as u32;

        let pattern = (pattern_id, pattern.clone_with_id(next_hs_id));
        self.patterns.push(pattern);
        pattern_id
    }

    /// Attempts to compile all the patterns, returning a [`PatternSet`] if successful
    pub fn try_compile(self) -> Result<PatternSet, PatternSetError> {
        // Because of how patterns are added to the builder, they are guaranteed to have a unique
        // n+1 hyperscan id.
        let database = BlockDatabase::try_new(self.patterns.iter().map(|(_, pat)| pat))?;
        let database = Arc::new(database);
        // Hyperscan supports libpcre(2) syntax, even though it has different semantics.
        // https://intel.github.io/hyperscan/dev-reference/compilation.html#semantics
        //
        // This means that because database compilation succeeded, all the regex patterns
        // contain valid pcre2 syntax, so we augment the Pattern with a backing regex to provide
        // captures and true start-of-match detection.
        let patterns: Result<Vec<PatternWithId>, PatternSetError> = self
            .patterns
            .into_iter()
            .map(|(id, hs_pattern)| {
                // NOTE: An error here should never occur (see above regarding successful Hyperscan compilation)
                let pattern: Pattern = hs_pattern.try_into().map_err(PatternSetError::Regex)?;
                Ok(PatternWithId { id, pattern })
            })
            .collect();
        let patterns = patterns?;
        let pattern_set = PatternSet {
            matcher_id: self.matcher_id,
            database,
            patterns,
        };

        Ok(pattern_set)
    }
}

#[rustfmt::skip]
#[cfg(test)]
mod tests {
    use super::{PatternSet, PatternSetBuilder};
    use crate::matcher::{MatcherId, PatternId};
    use vectorscan::Pattern as HsPattern;

    /// The [`PatternSetBuilder`] should assign [`vectorscan::scan::PatternId`] ids from 0 to n.
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
            let set = PatternSet::new(Default::default()).pattern(pat_a).pattern(pat_b).pattern(pat_c);
            assert_eq!(
                set.try_compile().unwrap().patterns.iter().map(|np| np.inner().hs().id()).collect::<Vec<_>>(),
                vec![0, 1, 2]
            );
        }
    }

    /// The PatternSet doesn't require expressions to be unique.
    #[test]
    fn allow_duplicate_expressions() {
        let pat1 = HsPattern::new("abc?").try_build().unwrap();
        let pat2 = pat1.clone();
        let set = PatternSet::new(0.into()).pattern(pat1).pattern(pat2);
        assert!(set.try_compile().is_ok_and(|set| set.len() == 2));
    }

    /// The caller doesn't need to consume the returned id.
    #[test]
    fn caller_id_none() {
        let pat1 = HsPattern::new("abc?").try_build().unwrap();
        let pat2 = HsPattern::new("def?").try_build().unwrap();
        let pat3 = HsPattern::new("ghi?").try_build().unwrap();
        let pat4 = HsPattern::new("jkl?").try_build().unwrap();
        let pat5 = HsPattern::new("mno?").try_build().unwrap();

        let m_id = MatcherId(10);
        let mut set = PatternSet::new(m_id)
            .pattern(pat1)
            .pattern(pat2);
        let pid3 = set.add_pattern(pat3);
        set = set.pattern(pat4).pattern(pat5);

        let set = set.try_compile().unwrap();
        assert_eq!(set.len(), 5);
        assert_eq!(pid3, PatternId(2, m_id));
    }
}
