use secrets_core::engine::{Engine, EngineBuilder};
use secrets_core::matcher::hyperscan::pattern_set::PatternSet;
use secrets_core::matcher::hyperscan::Hyperscan;
use secrets_core::matcher::Matcher;
use secrets_core::rule::Rule;
use secrets_core::{engine, ureq, vectorscan, Validator};

pub use engine::ValidationResult;
pub use secrets_core::location::PointSpan;
pub use secrets_core::rule::RuleId;
use secrets_core::validator::http::{
    GeneratorResult, HttpValidator, HttpValidatorBuilder, NextAction, RequestGeneratorBuilder,
    ResponseParserBuilder,
};
use secrets_core::validator::Candidate;
pub use secrets_core::validator::{SecretCategory, Severity};

/// This module is for (temporary) testing purposes only

fn build_test_rules() -> (
    Vec<Matcher>,
    Vec<Rule>,
    Vec<Box<dyn Validator + Send + Sync>>,
) {
    let rule_id_1: RuleId = "datadog-api-key".into();
    let pattern_1 = vectorscan::Pattern::new(
        r#"\b(?is)(?<prelude>(?:datadog|dd|ddog)(?:.{0,40}))(?-is)\b(?<candidate>[[:xdigit:]]{32})\b"#,
    )
    .try_build()
    .unwrap();

    let mut set = PatternSet::new(0.into());
    let pid_1 = set.add_pattern(pattern_1);
    let set = set.try_compile().unwrap();
    let hyperscan = Matcher::Hyperscan(Hyperscan::new(set));

    let val1 = build_simple_http(&rule_id_1, "https://api.datad0g.com");
    let val_id_1 = val1.id().clone();

    let val1: Box<dyn Validator + Send + Sync> = Box::new(val1);

    (
        vec![hyperscan],
        vec![Rule::new(rule_id_1, pid_1, val_id_1, vec![], vec![])],
        vec![val1],
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
    let (matchers, rules, validators) = build_test_rules();
    EngineBuilder::new()
        .matchers(matchers)
        .rules(rules)
        .validators(validators)
        .build()
}

fn build_simple_http(rule_id: &RuleId, url: &str) -> HttpValidator {
    let url = url.to_string();
    let url_generator =
        Box::new(move |_c: &Candidate| -> GeneratorResult<String> { Ok(url.clone()) });
    let agent = ureq::Agent::new();
    let mut request_generator = RequestGeneratorBuilder::http_get(agent, url_generator);
    request_generator = request_generator.header("Content-Type", "application/json");
    request_generator = request_generator.dynamic_header(
        "DD-API-KEY",
        Box::new(|c: &Candidate| {
            Ok(c.rule_match
                .captures
                .get("candidate")
                .unwrap()
                .inner
                .clone())
        }),
    );

    request_generator = request_generator.header("User-Agent", "Datadog/StaticAnalysis");
    let request_generator = request_generator.build();

    let mut response_handler = ResponseParserBuilder::new();
    response_handler = response_handler.on_status_code(
        200,
        NextAction::ReturnResult(SecretCategory::Valid(Severity::Error)),
    );
    response_handler = response_handler.on_status_code(
        403,
        NextAction::ReturnResult(SecretCategory::Invalid(Severity::Info)),
    );
    response_handler = response_handler.set_default(NextAction::ReturnResult(
        SecretCategory::Inconclusive(Severity::Info),
    ));
    let response_handler = response_handler.build();

    HttpValidatorBuilder::new(
        format!("validator-http_{}", rule_id).into(),
        request_generator,
        response_handler,
    )
    .build()
}

#[cfg(test)]
mod tests {
    use crate::temp_integration_test::build_secrets_engine;
    use secrets_core::rule::RuleMatch;
    use std::path::PathBuf;

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

        let mut candidates = engine.scan(&PathBuf::new(), file_contents.as_bytes()).unwrap();
        candidates.sort_by_key(|cand| cand.rule_match.matched.byte_span.start_index);

        let rule_match = &candidates[0].rule_match;
        assert_eq!(rule_match.rule_id.as_str(), "datadog-api-key");
        assert_eq!(parse_capture(rule_match, "candidate"), Some("918d1aaf6e301c1aa4ff315396459906"));

        let rule_match = &candidates[1].rule_match;
        assert_eq!(rule_match.rule_id.as_str(), "datadog-api-key");
        assert_eq!(parse_capture(rule_match, "candidate"), Some("861fd58f910308a8d9986c81e776be59"));

        assert!(candidates.get(2).is_none());
    }
}
