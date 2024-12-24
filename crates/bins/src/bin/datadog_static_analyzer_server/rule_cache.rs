use dashmap::DashMap;
use kernel::analysis::ddsa_lib::JsRuntime;
use kernel::model::rule::RuleInternal;
use server::model::analysis_request::{AnalysisRequest, ServerRule};
use server::model::analysis_response::RuleResponse;
use server::request::process_analysis_request;
use std::sync::Arc;

/// A [`ServerRule`] with its corresponding pre-compiled [`RuleInternal`].
#[derive(Debug)]
pub struct CompiledServerRule {
    rule: ServerRule,
    /// The rule (from converted from the "raw" `ServerRule`), which has a pre-compiled tree-sitter query.
    internal: RuleInternal,
}

impl CompiledServerRule {
    /// Returns a reference to the [`ServerRule`] that this cache represents.
    pub fn inner(&self) -> &ServerRule {
        &self.rule
    }

    /// Returns a reference to the [`RuleInternal`] that this cache represents.
    pub fn as_internal(&self) -> &RuleInternal {
        &self.internal
    }
}

/// A cache of compiled [`RuleInternal`], keyed by the rule name. Previously-cached values are overwritten
/// if there is a rule name collision.
#[derive(Debug)]
pub struct RuleCache(DashMap<String, Arc<CompiledServerRule>>);

/// A return value from looking up or inserting a value into a [`RuleCache`]. `is_update` will be `true`
/// if this value previously existed in the map and was updated, or `false` if either a
/// previous value was returned or the rule name has been cached for the first time.
#[derive(Debug)]
pub(crate) struct CachedValue {
    pub(crate) rule: Arc<CompiledServerRule>,
    pub(crate) is_update: bool,
}

impl RuleCache {
    /// Returns a new `RuleCache` with a capacity of 0.
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self(DashMap::new())
    }

    /// Returns a [`CachedValue`] for the provided [`ServerRule`], utilizing a cache under the hood.
    pub fn get_or_insert_from(&self, server_rule: ServerRule) -> Result<CachedValue, &'static str> {
        if let Some(cached) = self.0.get(&server_rule.name) {
            // (Note that even if the cache has this rule re-written after this function returns, the caller
            // will still hold an owned reference to the original compiled rule, so there is no race).

            // Only return the cached value if it's an exact match of the incoming `server_rule`.
            // This check is necessary because the HashMap is keyed by rule name, so there
            // could be a collision if the rule is updated.
            if cached.rule == server_rule {
                return Ok(CachedValue {
                    rule: Arc::clone(cached.value()),
                    is_update: false,
                });
            }
        }
        // If there was no cached rule (or the rule wasn't an exact match), compile and cache a new rule.
        let rule_internal = RuleInternal::try_from(server_rule.clone())?;
        let rule_name = server_rule.name.clone();
        let compiled = Arc::new(CompiledServerRule {
            rule: server_rule,
            internal: rule_internal,
        });
        let cloned_rule = Arc::clone(&compiled);
        let existing = self.0.insert(rule_name, compiled);
        Ok(CachedValue {
            rule: cloned_rule,
            is_update: existing.is_some(),
        })
    }
}

/// Executes the [`AnalysisRequest`], optionally utilizing a cache for compiled rules.
pub(crate) fn cached_analysis_request(
    runtime: &mut JsRuntime,
    request: AnalysisRequest<ServerRule>,
    cache: Option<&RuleCache>,
) -> Result<Vec<RuleResponse>, &'static str> {
    if let Some(cache) = cache {
        // A vec to hold compiled rules as owned values so their contained `RuleInternal` can be passed in as a Vec<&RuleInternal>.
        // (This is necessary because `Arc<T>` doesn't impl `Borrow<T>`)
        let mut compiled_rules = Vec::with_capacity(request.rules.len());
        for server_rule in request.rules {
            let cached = cache.get_or_insert_from(server_rule)?;
            // (Since we've had a mutable reference to the `JsRuntime` for this whole scoped job,
            // we know the runtime's v8::Script cache cannot change out from under us.
            // Thus, there is no potential race in the time after clearing the cache
            // but before actually executing the JavaScript rule).
            if cached.is_update {
                // The runtime's `v8::Script` cache is keyed only by name -- we need to manually clear it.
                runtime.clear_rule_cache(&cached.rule.inner().name);
            }
            compiled_rules.push(cached.rule);
        }
        let rule_internals = compiled_rules
            .iter()
            .map(|rule| rule.as_internal())
            .collect::<Vec<_>>();
        let req_with_compiled: AnalysisRequest<&RuleInternal> = AnalysisRequest {
            filename: request.filename,
            language: request.language,
            file_encoding: request.file_encoding,
            code_base64: request.code_base64,
            rules: rule_internals,
            configuration_base64: request.configuration_base64,
            options: request.options,
        };
        process_analysis_request(req_with_compiled, runtime)
    } else {
        let mut rule_internals = Vec::with_capacity(request.rules.len());
        for server_rule in request.rules {
            let rule_internal = RuleInternal::try_from(server_rule)?;
            // The runtime's `v8::Script` cache is keyed only by name -- we need to manually clear it.
            runtime.clear_rule_cache(&rule_internal.name);
            rule_internals.push(rule_internal);
        }
        let req_with_internal: AnalysisRequest<RuleInternal> = AnalysisRequest {
            filename: request.filename,
            language: request.language,
            file_encoding: request.file_encoding,
            code_base64: request.code_base64,
            rules: rule_internals,
            configuration_base64: request.configuration_base64,
            options: request.options,
        };
        process_analysis_request(req_with_internal, runtime)
    }
}

#[cfg(test)]
mod tests {
    use crate::datadog_static_analyzer_server::rule_cache::{cached_analysis_request, RuleCache};
    use kernel::analysis::ddsa_lib;
    use kernel::model::common::Language;
    use kernel::model::rule::{compute_sha256, RuleCategory, RuleSeverity, RuleType};
    use kernel::utils::encode_base64_string;
    use server::model::analysis_request::{AnalysisRequest, ServerRule};

    /// Tests that `cached_analysis_request` implements the (optional) cache properly.
    /// When enabled, this requires:
    /// * Updating the `RuleCache` cache
    /// * Updating the thread-local JavaScript runtime's `v8::Script` cache
    #[test]
    fn test_cached_analysis_request() {
        const RULE_NAME: &str = "ruleset/rule-name";
        let v8 = ddsa_lib::test_utils::cfg_test_v8();

        fn request_from(
            rule_name: &str,
            language: Language,
            rule: (&str, &str),
        ) -> AnalysisRequest<ServerRule> {
            let file_contents = "
def abc():
";
            let code_base64 = encode_base64_string(rule.0.to_string());
            let checksum = Some(compute_sha256(code_base64.as_bytes()));
            let ts_query_b64 = encode_base64_string(rule.1.to_string());
            let server_rule = ServerRule {
                name: rule_name.to_string(),
                short_description_base64: None,
                description_base64: None,
                category: Some(RuleCategory::BestPractices),
                severity: Some(RuleSeverity::Warning),
                language,
                rule_type: RuleType::TreeSitterQuery,
                entity_checked: None,
                code_base64,
                checksum,
                pattern: None,
                tree_sitter_query_base64: Some(ts_query_b64),
                arguments: vec![],
            };
            AnalysisRequest {
                filename: "file.py".to_string(),
                language: Language::Python,
                file_encoding: "utf-8".to_string(),
                code_base64: encode_base64_string(file_contents.to_string()),
                rules: vec![server_rule],
                configuration_base64: None,
                options: None,
            }
        }

        let req_v1 = request_from(
            RULE_NAME,
            Language::Python,
            (
                // language=javascript
                "\
function visit(captures) {
    const func = captures.get('func');
    addError(Violation.new('rule_v1', func));
}
",
                "(function_definition) @func",
            ),
        );
        let req_v2 = request_from(
            RULE_NAME,
            Language::Python,
            (
                // language=javascript
                "\
function visit(captures) {
    const funcName = captures.get('name');
    addError(Violation.new('rule_v2', funcName));
}
",
                "(function_definition name: (identifier) @name)",
            ),
        );

        // Test invariants:
        // Tests equality of rule name, which triggers a cache collision.
        assert_eq!(req_v1.rules[0].name, req_v2.rules[0].name);
        // Tests the clearing of `v8::Script` cache
        assert_ne!(req_v1.rules[0].code_base64, req_v2.rules[0].code_base64);
        // Tests the clearing of `RuleCache` cache`
        assert_ne!(
            req_v1.rules[0].tree_sitter_query_base64,
            req_v2.rules[0].tree_sitter_query_base64
        );

        for test_case in [None, Some(&RuleCache::new())] {
            let mut rt = v8.new_runtime();
            let rule_responses =
                cached_analysis_request(&mut rt, req_v1.clone(), test_case).unwrap();
            assert_eq!(rule_responses[0].violations[0].0.message, "rule_v1");
            if let Some(cache) = test_case {
                assert_eq!(
                    cache.0.get(RULE_NAME).unwrap().rule.code_base64,
                    req_v1.rules[0].code_base64
                );
            }

            let rule_responses =
                cached_analysis_request(&mut rt, req_v2.clone(), test_case).unwrap();
            assert_eq!(rule_responses[0].violations[0].0.message, "rule_v2");
            if let Some(cache) = test_case {
                assert_eq!(
                    cache.0.get(RULE_NAME).unwrap().rule.code_base64,
                    req_v2.rules[0].code_base64
                );
            }
        }
    }
}
