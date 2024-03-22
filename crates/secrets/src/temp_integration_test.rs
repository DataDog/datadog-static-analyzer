use secrets_core::engine::{Engine, EngineBuilder};
use secrets_core::matcher::hyperscan::pattern_set::PatternSet;
use secrets_core::matcher::hyperscan::Hyperscan;
use secrets_core::matcher::Matcher;
use secrets_core::rule::{Expression, MatchSource, Rule, RuleId};
use secrets_core::vectorscan;

/// This module is for (temporary) testing purposes only

fn build_test_rules() -> (Vec<Matcher>, Vec<Rule>) {
    let rule_id_1: RuleId = "datadog-app-key".into();
    let pattern_1 = vectorscan::Pattern::new(
        r#"\b(?is)(?<prelude>(?:datadog|dd|ddog)(?:.{0,40}))(?-is)\b(?<candidate>[[:xdigit:]]{40})\b"#,
    )
    .try_build()
    .unwrap();
    let rule_id_2: RuleId = "datadog-api-key".into();
    let pattern_2 = vectorscan::Pattern::new(
        r#"\b(?is)(?<prelude>(?:datadog|dd|ddog)(?:.{0,40}))(?-is)\b(?<candidate>[[:xdigit:]]{32})\b"#,
    )
    .try_build()
    .unwrap();
    let pattern_3 = vectorscan::Pattern::new(r#"\s"#).try_build().unwrap();

    let mut set = PatternSet::new(0.into());
    let pid_1 = set.add_pattern(pattern_1);
    let pid_2 = set.add_pattern(pattern_2);
    let pid_3 = set.add_pattern(pattern_3);
    let set = set.try_compile().unwrap();
    let hyperscan = Matcher::Hyperscan(Hyperscan::new(set));

    let stages_1 = vec![
        Expression::IsMatch {
            source: MatchSource::Prior,
            pattern_id: pid_1,
        },
        Expression::IsMatch {
            source: MatchSource::Capture("prelude".into()),
            pattern_id: pid_3,
        },
    ];
    let stages_2 = vec![
        Expression::IsMatch {
            source: MatchSource::Prior,
            pattern_id: pid_2,
        },
        Expression::IsMatch {
            source: MatchSource::Capture("prelude".into()),
            pattern_id: pid_3,
        },
    ];

    (
        vec![hyperscan],
        vec![
            Rule::new(rule_id_1, vec![], stages_1, vec![]),
            Rule::new(rule_id_2, vec![], stages_2, vec![]),
        ],
    )
}

pub fn shannon_entropy(data: impl IntoIterator<Item = char>, base: usize) -> f32 {
    let mut data_len = 0_usize;
    let mut entropy = 0.0;
    let mut counts = [0_usize; 256];

    for ch in data.into_iter() {
        counts[ch as usize] += 1;
        data_len += 1;
    }

    for count in counts.iter().filter(|&count| *count > 0).copied() {
        let p = (count as f32) / (data_len as f32);
        entropy -= p * p.log2()
    }

    entropy / (base as f32).log2()
}

/// Builds an [`Engine`] with hard-coded Datadog token detectors, to be used for testing.
pub fn build_secrets_engine() -> Engine {
    let (matchers, rules) = build_test_rules();
    EngineBuilder::new().matchers(matchers).rules(rules).build()
}

#[cfg(test)]
mod tests {
    use crate::temp_integration_test::build_secrets_engine;
    use secrets_core::rule::RuleMatch;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn parse_capture<'a>(rule_match: &'a RuleMatch, name: &str) -> Option<&'a str> {
        rule_match.captures.get(name).map(|cap| cap.as_str())
    }

    #[rustfmt::skip]
    #[test]
    fn datadog_key_detection() {
        let engine = build_secrets_engine();

        let file_contents = r#"// Create a client for the Datadog API
const client = await buildClient("918d1aaf6e301c1aa4ff315396459906");
//////////////////////////////////////////////////////////////////////


const DDOG_API_KEY = "861fd58f910308a8d9986c81e776be59";
//////////////////////////////////////////////////////////////////////


const DD_APP_KEY = "a0ef3594e77b5346791b02bdb1b2ea20c9057d61";
//////////////////////////////////////////////////////////////////////

// The key for the service
const APP_KEY = "b5aec3083c1a1114efdaaa2416e70012a65a5ac0";
//////////////////////////////////////////////////////////////////////


const url = "https://github.com/DataDog/repository/blob/main/3380f4569079edec8b16bbd2bfd882ebe7b3ec30/file.txt";
//////////////////////////////////////////////////////////////////////
"#;
        let mut file = NamedTempFile::new().unwrap();
        file.write(file_contents.as_bytes()).unwrap();

        let mut candidates = engine.scan_file(file.path()).unwrap();
        candidates.sort_by_key(|cand| cand.rule_match.matched.byte_span.start_index);

        let rule_match = &candidates[0].rule_match;
        assert_eq!(rule_match.rule_id.as_ref(), "datadog-api-key");
        assert_eq!(parse_capture(rule_match, "candidate"), Some("918d1aaf6e301c1aa4ff315396459906"));

        let rule_match = &candidates[1].rule_match;
        assert_eq!(rule_match.rule_id.as_ref(), "datadog-api-key");
        assert_eq!(parse_capture(rule_match, "candidate"), Some("861fd58f910308a8d9986c81e776be59"));

        let rule_match = &candidates[2].rule_match;
        assert_eq!(rule_match.rule_id.as_ref(), "datadog-app-key");
        assert_eq!(parse_capture(rule_match, "candidate"), Some("a0ef3594e77b5346791b02bdb1b2ea20c9057d61"));

        assert!(candidates.get(3).is_none());
    }
}
