// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use secrets_core::matcher::hyperscan::{HyperscanBuilder, HyperscanBuilderError};
use secrets_core::rule::RuleMatch;

/// The capture name used when a regex is augmented with proximity keywords, named in a manner to
/// avoid unintentional collisions with the original pattern's capture names.
///
/// This is used to restore the original pattern when processing matches.
pub(crate) const PROXIMITY_MAGIC: &str = "__PROXIMITY_MAGIC_5f3759df__";

#[derive(Debug, thiserror::Error)]
pub enum HyperscanMatcherError {
    /// An error that indicates that the supplied `original_pattern` is a valid pattern, but a transformation makes it invalid.
    #[error("can't {transformation_summary} `{original_pattern}`: {remediation}")]
    PatternTransformation {
        original_pattern: String,
        /// A short, human-friendly string describing the transformation attempted.
        ///
        /// For example: "add proximity keywords to"
        transformation_summary: String,
        /// The suggestion for the user to fix the error.
        remediation: String,
    },
    #[error(transparent)]
    Builder(#[from] HyperscanBuilderError),
}

/// Prepends a regex pattern with an additional pattern that checks if the given set of keywords is
/// within a range of the target pattern
///
/// This function also verifies that the original pattern would compile in the first place.
///
/// The `max_distance` is the wildcard space allowed between the end of the keyword and start of the match candidate.
pub(crate) fn build_proximity_pattern<'a>(
    pattern: &str,
    keywords: impl IntoIterator<Item = &'a str>,
    max_distance: usize,
) -> Result<String, HyperscanMatcherError> {
    HyperscanBuilder::check_pattern(pattern).map_err(HyperscanMatcherError::Builder)?;

    // A whitespace-trimmed list of strings
    let escaped_keywords = keywords
        .into_iter()
        .map(|str| str.trim_matches(char::is_whitespace))
        .filter(|&str| !str.is_empty())
        .map(HyperscanBuilder::format_escaped_hex)
        .collect::<Vec<_>>();

    if escaped_keywords.is_empty() {
        return Ok(pattern.to_string());
    }

    let transformed = format!(
        "(?i)(?:(?:{})(?s).{{0,{}}}(?-s))(?-i)(?<{}>{})",
        escaped_keywords.join("|"),
        max_distance,
        PROXIMITY_MAGIC,
        pattern
    );
    HyperscanBuilder::check_pattern(&transformed).map_err(|_| {
        HyperscanMatcherError::PatternTransformation {
            original_pattern: pattern.to_string(),
            transformation_summary: "add proximity keywords to".to_string(),
            remediation: "try reducing the proximity max distance".to_string(),
        }
    })?;
    Ok(transformed)
}

/// Given a [`Candidate`], checks if it resulted from a pattern transformed by [`build_proximity_pattern`],
/// and if so, mutates the candidate to make it as if the proximity transformation never occurred.
///
/// This function is a no-op if the candidate was not originally transformed.
pub(crate) fn restore_rule_match_mut(rule_match: &mut RuleMatch) -> bool {
    if let Some(l_str) = rule_match.captures.remove(PROXIMITY_MAGIC) {
        // This `LocatedString` represents the original regex we wrapped, so whatever was
        // captured here is what would've been the entire pattern had we not transformed it.
        let _ = std::mem::replace(&mut rule_match.matched, l_str);
        true
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use crate::proximity::{
        build_proximity_pattern, restore_rule_match_mut, HyperscanMatcherError, PROXIMITY_MAGIC,
    };
    use secrets_core::location::PointLocator;
    use secrets_core::matcher::hyperscan::{Hyperscan, HyperscanBuilder};
    use secrets_core::matcher::{PatternId, PatternMatch};
    use secrets_core::rule::RuleMatch;
    use secrets_core::rule_evaluator::CheckedMatch;

    fn build_hs(
        proximity_keywords: &[&'static str],
        max_distance: usize,
    ) -> Result<(Hyperscan, PatternId, PatternId), HyperscanMatcherError> {
        let proximity_keywords = proximity_keywords.to_vec();
        let base_pattern = "(?<foo>[[:xdigit:]]{8})";
        let mut hs = HyperscanBuilder::new(1.into());
        let base_pid = hs.add_regex(base_pattern).unwrap();
        let proximity_pattern =
            build_proximity_pattern(base_pattern, proximity_keywords, max_distance)?;
        let proximity_pid = hs.add_regex(proximity_pattern)?;
        let hs = hs.try_compile()?;
        Ok((hs, base_pid, proximity_pid))
    }

    fn has_match(hs: &mut Hyperscan, data: &str, pattern_id: PatternId) -> bool {
        hs.scan_data(data.as_bytes())
            .unwrap()
            .into_iter()
            .any(|pm| pm.pattern_id() == pattern_id)
    }

    #[rustfmt::skip]
    fn get_match<'d>(hs: &'d mut Hyperscan, data: &'d str, pattern_id: PatternId) -> Option<PatternMatch<'d>> {
        hs.scan_data(data.as_bytes())
            .unwrap()
            .into_iter()
            .find(|pm| pm.pattern_id() == pattern_id)
            .clone()
    }

    #[test]
    fn add_proximity_keywords() {
        let (mut hs, base_pid, proximity_pid) = build_hs(&["bravo"], 20).unwrap();

        let text_1 = "access key: e5e604da";
        assert!(has_match(&mut hs, text_1, base_pid));
        assert!(!has_match(&mut hs, text_1, proximity_pid));

        let text_2 = "[bravo] access key: e5e604da";
        assert!(has_match(&mut hs, text_2, proximity_pid));

        // Just outside the proximity range (21 vs 20)
        let text_3 = "[bravo] ------ access key: e5e604da";
        //                  |         21        |
        assert!(!has_match(&mut hs, text_3, proximity_pid));
    }

    #[test]
    fn proximity_keyword_escapes() {
        let (mut hs, _base_pid, proximity_pid) = build_hs(&["bra{3}vo"], 20).unwrap();

        let text_1 = "bravo: e5e604da";
        assert!(!has_match(&mut hs, text_1, proximity_pid));

        let text_2 = "braaavo: e5e604da";
        assert!(!has_match(&mut hs, text_2, proximity_pid));

        let text_3 = "bra{3}vo: e5e604da";
        assert!(has_match(&mut hs, text_3, proximity_pid));
    }

    #[test]
    fn proximity_keyword_invalid() {
        let result = build_hs(&["bravo"], 128);
        assert!(result.is_ok());
        // An (arbitrary) large int that is beyond Hyperscan's capability to compile
        let result = build_hs(&["bravo"], u16::MAX as usize);
        assert!(matches!(
            result.unwrap_err(),
            HyperscanMatcherError::PatternTransformation { .. }
        ));
    }

    /// Asserts that proximity transformation _does_ introduce "side effects" to resultant [`PatternMatch`]es.
    /// However, the original pattern can be derived from the wrapping [`PROXIMITY_MAGIC`] capture.
    #[test]
    fn proximity_keyword_derive_original() {
        let (mut hs, _base_pid, proximity_pid) = build_hs(&["bravo"], 20).unwrap();

        let text_1 = "hotel: e5e604da";
        let text_2 = "bravo: e5e604da";
        assert!(!has_match(&mut hs, text_1, proximity_pid));

        let pm = get_match(&mut hs, text_2, proximity_pid).unwrap();
        assert_eq!(pm.entire().as_bytes(), b"bravo: e5e604da");
        //                                   _______ <- The proximity transformation expanded the regex to capture these bytes
        let pre_transform_capture = pm.captures().name(PROXIMITY_MAGIC).unwrap();
        assert_eq!(pre_transform_capture.as_bytes(), b"e5e604da")
    }

    /// Tests that we can mutate a [`RuleMatch`] to reverse the side effects of the proximity transformation.
    #[test]
    fn proximity_restore_rule_match() {
        let (mut hs, _base_pid, proximity_pid) = build_hs(&["bravo"], 20).unwrap();

        let text_1 = "bravo: e5e604da";
        let pm = get_match(&mut hs, text_1, proximity_pid).unwrap();
        assert_eq!(pm.entire().as_bytes(), b"bravo: e5e604da");

        let checked_match = CheckedMatch(pm);
        let (matched, captures) = checked_match
            .try_into_owned_components(&PointLocator::new(text_1.as_bytes()))
            .unwrap();
        let mut rm = RuleMatch {
            rule_id: "rule-id".into(),
            matched,
            captures,
        };
        assert_eq!(rm.matched.as_str(), "bravo: e5e604da");
        assert!(rm.captures.get(PROXIMITY_MAGIC).is_some());

        assert!(restore_rule_match_mut(&mut rm));

        assert_eq!(rm.matched.as_str(), "e5e604da");
        assert!(rm.captures.get(PROXIMITY_MAGIC).is_none());
    }
}
