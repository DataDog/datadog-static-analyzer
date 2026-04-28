use dashmap::DashMap;
use kernel::analysis::ddsa_lib::JsRuntime;
use kernel::model::rule::RuleInternal;
use server::model::analysis_request::{AnalysisRequest, ServerRule};
use server::model::analysis_response::RuleResponse;
use server::request::process_analysis_request;
use std::sync::Arc;
use std::time::Duration;

/// A [`ServerRule`] with its corresponding pre-compiled [`RuleInternal`].
#[derive(Debug)]
pub struct CompiledServerRule {
    rule: ServerRule,
    /// The rule (from converted from the "raw" `ServerRule`), which has a pre-compiled tree-sitter query.
    internal: RuleInternal,
}

impl CompiledServerRule {
    /// Returns a reference to the [`RuleInternal`] that this cache represents.
    pub fn as_internal(&self) -> &RuleInternal {
        &self.internal
    }
}

/// A cache of compiled [`RuleInternal`], keyed by the rule name. Previously-cached values are overwritten
/// if there is a rule name collision.
#[derive(Debug)]
pub struct RuleCache(DashMap<String, Arc<CompiledServerRule>>);

impl RuleCache {
    /// Returns a new `RuleCache` with a capacity of 0.
    pub fn new() -> Self {
        Self(DashMap::new())
    }

    /// Returns the [`CompiledServerRule`] for the provided [`ServerRule`], utilizing a cache under the hood.
    pub fn get_or_insert_from(
        &self,
        server_rule: ServerRule,
    ) -> Result<Arc<CompiledServerRule>, &'static str> {
        if let Some(cached) = self.0.get(&server_rule.name) {
            // (Note that even if the cache has this rule re-written after this function returns, the caller
            // will still hold an owned reference to the original compiled rule, so there is no race).

            // Only return the cached value if it's an exact match of the incoming `server_rule`.
            // This check is necessary because the HashMap is keyed by rule name, so there
            // could be a collision if the rule is updated.
            if cached.rule == server_rule {
                return Ok(Arc::clone(cached.value()));
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
        self.0.insert(rule_name, compiled);
        Ok(cloned_rule)
    }
}

/// Executes the [`AnalysisRequest`], optionally utilizing a cache for compiled rules.
pub(crate) fn cached_analysis_request(
    runtime: &mut JsRuntime,
    request: AnalysisRequest<ServerRule>,
    timeout: Option<Duration>,
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
            let internal = cached.as_internal();
            let _ = runtime.evict_script_if_stale(&internal.name, &internal.code);
            compiled_rules.push(cached);
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
        process_analysis_request(req_with_compiled, runtime, timeout)
    } else {
        let mut rule_internals = Vec::with_capacity(request.rules.len());
        for server_rule in request.rules {
            let rule_internal = RuleInternal::try_from(server_rule)?;
            let _ = runtime.evict_script_if_stale(&rule_internal.name, &rule_internal.code);
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
        process_analysis_request(req_with_internal, runtime, timeout)
    }
}

#[cfg(test)]
mod tests {
    use crate::datadog_static_analyzer_server::rule_cache::{cached_analysis_request, RuleCache};
    use kernel::analysis::ddsa_lib;
    use kernel::model::common::Language;
    use kernel::model::rule::{compute_sha256, RuleCategory, RuleSeverity, RuleType};
    use kernel::utils::encode_base64_string;
    use server::model::analysis_request::{AnalysisRequest, AnalysisRequestOptions, ServerRule};

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
            language,
            file_encoding: "utf-8".to_string(),
            code_base64: encode_base64_string(file_contents.to_string()),
            rules: vec![server_rule],
            configuration_base64: None,
            options: Some(AnalysisRequestOptions {
                log_output: Some(true),
                use_tree_sitter: None,
            }),
        }
    }

    /// `cached_analysis_request` operates [RuleCache] properly.
    #[test]
    fn test_cached_analysis_request() {
        const RULE_NAME: &str = "ruleset/rule-name";
        let v8 = ddsa_lib::test_utils::cfg_test_v8();

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
                cached_analysis_request(&mut rt, req_v1.clone(), None, test_case).unwrap();
            assert_eq!(rule_responses[0].violations[0].0.message, "rule_v1");
            if let Some(cache) = test_case {
                assert_eq!(
                    cache.0.get(RULE_NAME).unwrap().rule.code_base64,
                    req_v1.rules[0].code_base64
                );
            }

            let rule_responses =
                cached_analysis_request(&mut rt, req_v2.clone(), None, test_case).unwrap();
            assert_eq!(rule_responses[0].violations[0].0.message, "rule_v2");
            if let Some(cache) = test_case {
                assert_eq!(
                    cache.0.get(RULE_NAME).unwrap().rule.code_base64,
                    req_v2.rules[0].code_base64
                );
            }
        }
    }

    /// `cached_analysis_request` operates the v8::UnboundScript cache of JSRuntime.
    #[test]
    fn test_cached_analysis_request_runtime_script_cache() {
        const RULE_NAME: &str = "ruleset/rule-name";
        let v8 = ddsa_lib::test_utils::cfg_test_v8();
        let cache = RuleCache::new();

        let req_v1 = request_from(
            RULE_NAME,
            Language::Python,
            (
                // language=javascript
                "function visit(captures) { console.log('rule_v1'); }",
                "(function_definition) @func",
            ),
        );
        let req_v2 = request_from(
            RULE_NAME,
            Language::Python,
            (
                // language=javascript
                "function visit(captures) { console.log('rule_v2'); }",
                "(function_definition) @func",
            ),
        );

        // Test invariants:
        // Tests equality of rule name, which triggers a cache collision.
        assert_eq!(req_v1.rules[0].name, req_v2.rules[0].name);
        // Tests the clearing of `v8::Script` cache
        assert_ne!(req_v1.rules[0].code_base64, req_v2.rules[0].code_base64);

        // Two runtimes to simulate two threads. Thus, there are two v8::UnboundScript caches, but the entrypoint is the same `RuleCache`
        let mut rt_a = v8.new_runtime();
        let mut rt_b = v8.new_runtime();

        let resp = cached_analysis_request(&mut rt_a, req_v1.clone(), None, Some(&cache)).unwrap();
        assert_eq!(resp[0].output.as_ref().unwrap(), "rule_v1");

        let resp = cached_analysis_request(&mut rt_b, req_v2.clone(), None, Some(&cache)).unwrap();
        assert_eq!(resp[0].output.as_ref().unwrap(), "rule_v2");

        // `rt_a` still contains a v8::UnboundScript for `req_v1`.
        // `cached_analysis_request` must correctly instruct `rt_a` to clear its cache for `RULE_NAME`.
        let resp = cached_analysis_request(&mut rt_a, req_v2.clone(), None, Some(&cache)).unwrap();
        assert_eq!(resp[0].output.as_ref().unwrap(), "rule_v2");
    }
}
