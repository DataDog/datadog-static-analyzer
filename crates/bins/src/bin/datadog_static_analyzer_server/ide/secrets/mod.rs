pub mod endpoints;
mod models;

#[cfg(test)]
mod tests {
    use crate::datadog_static_analyzer_server::ide::ide_routes;
    use crate::datadog_static_analyzer_server::secret_scanner_cache::SecretScannerCache;
    use crate::SECRET_SCANNER_CACHE;
    use rocket::{
        http::{ContentType, Status},
        local::blocking::Client,
        uri,
    };
    use serde_json::Value as JsonValue;

    fn dispatch_scan(body: String) -> JsonValue {
        SECRET_SCANNER_CACHE.get_or_init(SecretScannerCache::new);
        let rocket = rocket::build().mount("/", ide_routes());
        let client = Client::tracked(rocket).expect("valid rocket instance");
        let response = client
            .post(uri!(super::endpoints::post_scan_secrets))
            .header(ContentType::JSON)
            .body(body)
            .dispatch();
        assert_eq!(response.status(), Status::Ok);
        serde_json::from_str(&response.into_string().unwrap()).expect("valid JSON")
    }

    fn foo_bar_rule_json() -> &'static str {
        r#"{
            "id": "test-rule",
            "attributes": {
                "name": "Test Rule",
                "description": "A test rule",
                "pattern": "FOO(BAR|BAZ)",
                "sds_id": "sds-123",
                "priority": "medium"
            }
        }"#
    }

    fn scan_body(rule_json: &str) -> String {
        format!(
            r#"{{ "filename": "myfile", "code": "FOO\nFOOBAR\nFOOBAZ\nCAT", "rules": [{rule_json}] }}"#
        )
    }

    /// End-to-end wiring: request deserializes, the API-type parser closure runs, and the
    /// response serializes with `rule_id` / `filename` carried through.
    #[test]
    fn scan_secrets_happy_path() {
        let response = dispatch_scan(scan_body(foo_bar_rule_json()));

        assert!(response["errors"].as_array().unwrap().is_empty());
        let rule_responses = response["rule_responses"].as_array().unwrap();
        assert_eq!(rule_responses.len(), 1);
        assert_eq!(rule_responses[0]["rule_id"], "test-rule");
        assert_eq!(rule_responses[0]["filename"], "myfile");
    }

    /// Covers our `"Failed to parse secret rule"` wrapping on the `SecretRuleApiType`
    /// deserialization branch.
    #[test]
    fn scan_secrets_reports_malformed_rule_json() {
        let response = dispatch_scan(scan_body(r#"{"id": "x"}"#));

        let errors = response["errors"].as_array().unwrap();
        assert_eq!(errors.len(), 1);
        assert!(
            errors[0]
                .as_str()
                .unwrap()
                .contains("Failed to parse secret rule"),
            "unexpected error: {}",
            errors[0]
        );
    }

    /// Covers our `"Failed to convert secret rule"` wrapping on the `TryFrom` branch —
    /// proves the API-type → `SecretRule` conversion is actually invoked.
    #[test]
    fn scan_secrets_reports_invalid_priority() {
        let rule = r#"{
            "id": "bad-priority",
            "attributes": {
                "name": "x",
                "description": "x",
                "pattern": "FOO",
                "sds_id": "sds-x",
                "priority": "not-a-priority"
            }
        }"#;
        let response = dispatch_scan(scan_body(rule));

        let errors = response["errors"].as_array().unwrap();
        assert_eq!(errors.len(), 1);
        assert!(
            errors[0]
                .as_str()
                .unwrap()
                .contains("Failed to convert secret rule"),
            "unexpected error: {}",
            errors[0]
        );
    }

    /// Covers the `retain(|m| !m.is_suppressed)` in our response filter: suppressed matches
    /// must not leak into the response, but the surrounding `SecretResult` still comes back
    /// when at least one match survives.
    #[test]
    fn scan_secrets_strips_suppressed_matches_from_result() {
        // Line 1: FOOBAR           (match, not suppressed)
        // Line 2: #no-dd-secrets
        // Line 3: FOOBAZ           (match, suppressed by directive on line 2)
        let body = format!(
            r##"{{ "filename": "myfile", "code": "FOOBAR\n#no-dd-secrets\nFOOBAZ", "rules": [{}] }}"##,
            foo_bar_rule_json()
        );
        let response = dispatch_scan(body);

        let rule_responses = response["rule_responses"].as_array().unwrap();
        assert_eq!(rule_responses.len(), 1);
        let matches = rule_responses[0]["matches"].as_array().unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(
            matches[0]["is_suppressed"], false,
            "filter should have removed any match with is_suppressed=true"
        );
    }

    /// Covers the `filter_map` in our response filter: a `SecretResult` whose matches are
    /// all suppressed must be dropped from the response entirely.
    #[test]
    fn scan_secrets_drops_result_when_all_matches_suppressed() {
        // Directive on line 1 suppresses line 2, which holds the only match.
        let body = format!(
            r##"{{ "filename": "myfile", "code": "#no-dd-secrets\nFOOBAR", "rules": [{}] }}"##,
            foo_bar_rule_json()
        );
        let response = dispatch_scan(body);

        assert!(response["errors"].as_array().unwrap().is_empty());
        assert!(
            response["rule_responses"].as_array().unwrap().is_empty(),
            "result with no surviving matches should be dropped"
        );
    }
}
