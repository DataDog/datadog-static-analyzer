// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::matcher::hyperscan::Pattern;
use crate::matcher::PatternId;
use std::collections::HashMap;
use std::sync::Arc;
use vectorscan::compiler::pattern::Expression;
use vectorscan::database::BlockDatabase;
use vectorscan::error::Error;

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

    /// Returns a reference to a [`NamedPattern`] with the given Hyperscan id.
    pub fn get(&self, id: vectorscan::scan::PatternId) -> Option<&NamedPattern> {
        self.patterns.get(id.0 as usize)
    }

    /// Returns a mutable reference to a [`NamedPattern`] with the given Hyperscan id.
    pub fn get_mut(&mut self, id: vectorscan::scan::PatternId) -> Option<&mut NamedPattern> {
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
pub struct NamedPattern {
    id: PatternId,
    pattern: Pattern,
}

impl NamedPattern {
    pub fn new(id: PatternId, pattern: Pattern) -> Self {
        Self { id, pattern }
    }

    pub fn id_arc(&self) -> PatternId {
        self.id.clone()
    }

    pub fn id(&self) -> &str {
        &self.id.0
    }

    pub fn inner(&self) -> &Pattern {
        &self.pattern
    }

    pub fn inner_mut(&mut self) -> &mut Pattern {
        &mut self.pattern
    }
}

/// A caller-provided id that allows the caller to associate the [`NamedPattern`] created with an arbitrary id.
pub(crate) type PatternSetReferenceId = Arc<str>;
pub(crate) type ReferenceIdMapping = HashMap<PatternSetReferenceId, Vec<PatternId>>;

#[derive(Debug, Default, Clone)]
pub(crate) struct PatternSetBuilder {
    /// Mapping from caller-provided reference ID to the generated [`NamedPattern`]s.
    mapping: ReferenceIdMapping,
    patterns: Vec<(PatternId, vectorscan::Pattern)>,
    regex_count: usize,
    literal_count: usize,
}

impl PatternSetBuilder {
    /// Creates a new builder for a [`PatternSet`].
    pub fn new() -> Self {
        Self {
            mapping: HashMap::new(),
            patterns: Vec::new(),
            regex_count: 0,
            literal_count: 0,
        }
    }

    /// Adds a [`vectorscan::Pattern`] to the set.
    ///
    /// If `reference_id` is provided, upon compilation, it will be linked with the generated [`NamedPattern`].
    // NOTE: The idea here is that we may want to perform under-the-hood optimizations that the caller
    // does not need to know about (for example, de-duplicating patterns, and thus mapping several
    // reference ids to the same pattern)
    pub fn pattern(
        mut self,
        pattern: vectorscan::Pattern,
        reference_id: Option<PatternSetReferenceId>,
    ) -> Self {
        let next_hs_id = self.patterns.len() as u32;
        // Currently, the `NamedPattern` name is just a string-equivalent of a one-based
        // numeric index, though this is arbitrary and could be really anything unique.
        let pattern_id = match pattern.expression() {
            Expression::Literal(_) => {
                self.literal_count += 1;
                format!("literal-{}", self.literal_count)
            }
            Expression::Regex(_) => {
                self.regex_count += 1;
                format!("regex-{}", self.regex_count)
            }
        };
        let pattern_id = Arc::<str>::from(pattern_id);
        let pattern_id = PatternId(pattern_id);

        if let Some(reference_id) = reference_id {
            self.mapping
                .entry(reference_id)
                .or_default()
                .push(pattern_id.clone());
        }

        let pattern = (pattern_id, pattern.clone_with_id(next_hs_id));
        self.patterns.push(pattern);
        self
    }

    /// Attempts to compile all the patterns, returning an [`PatternSet`] if successful
    pub fn try_compile(self) -> Result<(PatternSet, ReferenceIdMapping), PatternSetError> {
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
        let patterns: Result<Vec<NamedPattern>, PatternSetError> = self
            .patterns
            .into_iter()
            .map(|(id, hs_pattern)| {
                // NOTE: An error here should never occur (see above regarding successful Hyperscan compilation)
                let pattern: Pattern = hs_pattern.try_into().map_err(PatternSetError::Regex)?;
                Ok(NamedPattern { id, pattern })
            })
            .collect();
        let patterns = patterns?;
        let pattern_set = PatternSet { database, patterns };

        Ok((pattern_set, self.mapping))
    }
}

#[rustfmt::skip]
#[cfg(test)]
mod tests {
    use super::{PatternSet, PatternSetBuilder, PatternSetError};
    use std::sync::Arc;
    use vectorscan::Pattern as HsPattern;

    /// The [`PatternSetBuilder`] should assign [`vectorscan::scan::PatternId`] ids from 0 to n, regardless
    /// of whether the incoming pattern had an id already assigned.
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
            let set = PatternSet::new().pattern(pat_a, None).pattern(pat_b, None).pattern(pat_c, None);
            assert_eq!(
                set.try_compile().unwrap().0.patterns.iter().map(|np| np.inner().hs().id()).collect::<Vec<_>>(),
                vec![0, 1, 2]
            );
        }
    }

    /// The PatternSet doesn't require expressions to be unique.
    #[test]
    fn allow_duplicate_expressions() {
        let expression = "abc?";
        let pat1 = HsPattern::new(expression).try_build().unwrap();
        let pat2 = HsPattern::new(expression).try_build().unwrap();
        let set = PatternSet::new().pattern(pat1, None).pattern(pat2, None);
        assert!(set.try_compile().is_ok_and(|set| set.0.len() == 2));
    }

    /// The builder can map multiple patterns to the same caller-provided id.
    #[test]
    fn caller_id_duplicates() {
        let pat1 = HsPattern::new("abc?").try_build().unwrap();
        let pat2 = HsPattern::new("def?").try_build().unwrap();
        let pat3 = HsPattern::new("ghi?").try_build().unwrap();

        let unique_name = Arc::<str>::from("name-1");
        let dup_name = Arc::<str>::from("name-2");
        let set = PatternSet::new()
            .pattern(pat1, Some(dup_name.clone()))
            .pattern(pat2, Some(unique_name.clone()))
            .pattern(pat3, Some(dup_name.clone()));
        let (_, mapping) = set.try_compile().unwrap();

        assert_eq!(mapping.get(&dup_name), Some(&vec!["regex-1".into(), "regex-3".into()]));
        assert_eq!(mapping.get(&unique_name), Some(&vec!["regex-2".into()]));
    }

    /// The caller doesn't need to provide a reference id
    #[test]
    fn caller_id_none() {
        let pat1 = HsPattern::new("abc?").try_build().unwrap();
        let pat2 = HsPattern::new("def?").try_build().unwrap();
        let pat3 = HsPattern::new("ghi?").try_build().unwrap();

        let set = PatternSet::new()
            .pattern(pat1, None)
            .pattern(pat2, None)
            .pattern(pat3, None);
        let (set, mapping) = set.try_compile().unwrap();

        assert_eq!(set.len(), 3);
        assert_eq!(mapping.len(), 0);
    }
}
