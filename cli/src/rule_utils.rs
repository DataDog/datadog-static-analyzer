use anyhow::Result;
use kernel::model::common::Language;
use kernel::model::rule::Rule;
use kernel::model::ruleset::RuleSet;
use std::{fs::File, io::BufReader};

pub fn get_rulesets_from_file(file_path: &str) -> Result<Vec<RuleSet>> {
    let file = File::open(file_path)?;
    let reader = BufReader::new(file);
    get_rulesets_from_reader(reader)
}

pub fn get_rulesets_from_reader<R: std::io::Read>(reader: R) -> Result<Vec<RuleSet>> {
    Ok(serde_json::from_reader(reader)?)
}

pub fn get_languages_for_rules(rules: &[Rule]) -> Vec<Language> {
    let mut all_languages: Vec<Language> = rules.iter().map(|r| r.language).collect();
    all_languages.dedup();
    all_languages
}

#[cfg(test)]
mod tests {
    use kernel::model::{
        common::Language,
        rule::{RuleCategory, RuleSeverity, RuleType},
    };

    use super::*;

    // make sure we correctly get rulesets from a string
    #[test]
    fn parse_rulesets_from_string() {
        let data = r#"
[
    {
        "name": "python-inclusive",
        "description": "UnVsZXMgZm9yIFB5dGhvbiB0byBhdm9pZCBpbmFwcHJvcHJpYXRlIHdvcmRpbmcgaW4gdGhlIGNvZGUgYW5kIGNvbW1lbnRzLg==",
        "rules": [
            {
                "name": "python-inclusive/function-definition",
                "short_description": "Y2hlY2sgZnVuY3Rpb24gbmFtZXMgZm9yIHdvcmRpbmcgaXNzdWVz",
                "description": "RW5zdXJlIHRoYXQgc29tZSB3b3JkcyBhcmUgbm90IHVzZWQgaW4gdGhlIGNvZGViYXNlIGFuZCBzdWdnZXN0IHJlcGxhY2VtZW50IHdoZW4gYXBwcm9wcmlhdGUuCgpFeGFtcGxlcyBvZiByZXBsYWNlbWVudCBzdWdnZXN0aW9uczoKIC0gYGJsYWNrbGlzdGAgd2l0aCBgZGVueWxpc3RgCiAtIGB3aGl0ZWxpc3RgIHdpdGggYGFsbG93bGlzdGAKIC0gYG1hc3RlcmAgd2l0aCBgcHJpbWFyeWAKIC0gYHNsYXZlYCB3aXRoIGBzZWNvbmRhcnlg",
                "category": "CODE_STYLE",
                "severity": "NOTICE",
                "language": "PYTHON",
                "rule_type": "TREE_SITTER_QUERY",
                "entity_checked": null,
                "code": "LyoqCiAqIEEgdmlzaXQgZnVuY3Rpb24KICogQHBhcmFtIHthbnl9IG5vZGUgQW4gQVNUIGFueSBub2RlLgogKiBAcGFyYW0ge3N0cmluZ30gZmlsZW5hbWUgQSBmaWxlbmFtZSBwYXJhbS4KICogQHBhcmFtIHtzdHJpbmd9IGNvZGUgQSBjb2RlIHBhcmFtLgogKiBAcmV0dXJucwogKi8KZnVuY3Rpb24gdmlzaXQobm9kZSwgZmlsZW5hbWUsIGNvZGUpIHsKICBjb25zdCBGT1JCSURERU5fTkFNRVMgPSBuZXcgTWFwKCk7CgogIEZPUkJJRERFTl9OQU1FUy5zZXQoImJsYWNrbGlzdCIsICJkZW55bGlzdCIpOwogIEZPUkJJRERFTl9OQU1FUy5zZXQoIndoaXRlbGlzdCIsICJhbGxvd2xpc3QiKTsKICBGT1JCSURERU5fTkFNRVMuc2V0KCJtYXN0ZXIiLCAicHJpbWFyeSIpOwogIEZPUkJJRERFTl9OQU1FUy5zZXQoInNsYXZlIiwgInNlY29uZGFyeSIpOwoKICBmdW5jdGlvbiByZXBsYWNlKHRleHQsIHJlcGxhY2VtZW50LCBwb3NpdGlvbkluVGV4dCkgewogICAgdmFyIHJlc3VsdCA9IHRleHQuc3Vic3RyaW5nKDAsIHBvc2l0aW9uSW5UZXh0KTsKICAgIHZhciBwb3MgPSBwb3NpdGlvbkluVGV4dDsKICAgIGZvcih2YXIgaSA9IDA7IGkgPCByZXBsYWNlbWVudC5sZW5ndGg7IGkrKykgewogICAgICAgIHZhciBjID0gdGV4dC5jaGFyQXQocG9zKTsKICAgICAgICBpZihjID49IDY1ICYmIGMgPCA2NSArIDI2KSB7CiAgICAgICAgICAgIHJlc3VsdCArPSByZXBsYWNlbWVudC5jaGFyQXQoaSkudG9VcHBlckNhc2UoKTsKICAgICAgICB9IGVsc2UgewogICAgICAgICAgICByZXN1bHQgKz0gcmVwbGFjZW1lbnQuY2hhckF0KGkpLnRvTG93ZXJDYXNlKCk7CiAgICAgICAgfQogICAgICAgIHBvcyA9IHBvcyArIDE7CiAgICB9CiAgICByZXN1bHQgPSByZXN1bHQgKyB0ZXh0LnN1YnN0cmluZyhwb3MgKyAxLCB0ZXh0Lmxlbmd0aCk7CiAgICByZXR1cm4gcmVzdWx0OwogIH0KCiAgY29uc3QgaGFuZGxlcklkZW50aWZpZXIgPSAoaWRlbnRpZmllcikgPT4gewogICAgY29uc3QgYyA9IGdldENvZGUoaWRlbnRpZmllci5zdGFydCwgaWRlbnRpZmllci5lbmQsIGNvZGUpOwogICAgZm9yIChsZXQgW2tleSwgdmFsdWVdIG9mIEZPUkJJRERFTl9OQU1FUykgewogICAgICBjb25zdCBwb3MgPSBjLnRvTG93ZXJDYXNlKCkuaW5kZXhPZihrZXkpOwogICAgICBpZiAocG9zICE9PSAtMSkgewogICAgICAgIGNvbnN0IG5ld0NvZGUgPSByZXBsYWNlKGMsIHZhbHVlLCBwb3MpOwogICAgICAgIGNvbnN0IGVyciA9IGJ1aWxkRXJyb3IoCiAgICAgICAgICBpZGVudGlmaWVyLnN0YXJ0LmxpbmUsIGlkZW50aWZpZXIuc3RhcnQuY29sLAogICAgICAgICAgaWRlbnRpZmllci5lbmQubGluZSwgaWRlbnRpZmllci5lbmQuY29sLAogICAgICAgICAgYHN0cmluZyAke2tleX0gZGlzY291cmFnZWRgLAogICAgICAgICAgIldBUk5JTkciLAogICAgICAgICAgIkNPREVfU1RZTEUiCiAgICAgICAgKTsKICAgICAgICBjb25zdCBlID0gYnVpbGRFZGl0VXBkYXRlKAogICAgICAgICAgaWRlbnRpZmllci5zdGFydC5saW5lLCBpZGVudGlmaWVyLnN0YXJ0LmNvbCwKICAgICAgICAgIGlkZW50aWZpZXIuZW5kLmxpbmUsIGlkZW50aWZpZXIuZW5kLmNvbCwKICAgICAgICAgIG5ld0NvZGUKICAgICAgICApOwogICAgICAgIGNvbnN0IGYgPSBidWlsZEZpeChgdXNlICR7dmFsdWV9IGluc3RlYWRgLCBbZV0pOwogICAgICAgIGFkZEVycm9yKGVyci5hZGRGaXgoZikpOwogICAgICB9CiAgICB9CiAgfTsKCiAgaGFuZGxlcklkZW50aWZpZXIobm9kZS5jYXB0dXJlc1siZnVuY3Rpb25uYW1lIl0pOwogIGNvbnN0IHBhcmFtZXRlcnMgPSBub2RlLmNhcHR1cmVzWyJwYXJhbWV0ZXJzIl0uY2hpbGRyZW4uZmlsdGVyKGUgPT4gZS5hc3RUeXBlID09PSAiaWRlbnRpZmllciIpOwogIHBhcmFtZXRlcnMuZm9yRWFjaCgoZSkgPT4gewogICAgaGFuZGxlcklkZW50aWZpZXIoZSk7CiAgfSk7Cn0K",
                "checksum": "d2b54f17b9ecdd41d88671fb32276899b322de91fb46ed8e0bac65ad47bb0a0a",
                "pattern": null,
                "tree_sitter_query": "KGZ1bmN0aW9uX2RlZmluaXRpb24KICAgbmFtZTogKGlkZW50aWZpZXIpIEBmdW5jdGlvbm5hbWUKICAgcGFyYW1ldGVyczogKHBhcmFtZXRlcnMpIEBwYXJhbWV0ZXJzCik=",
                "variables": {},
                "tests": []
            }
        ]
    }
]
    "#;
        let res = get_rulesets_from_reader(data.as_bytes());
        assert!(&res.is_ok());
        let rulesets = res.expect("ruleset");
        assert_eq!(1, (&rulesets).len());
        let ruleset = rulesets.get(0).unwrap();
        assert_eq!(1, ruleset.rules.len());
        let rule = ruleset.rules.get(0).unwrap();
        assert_eq!(rule.name, "python-inclusive/function-definition");
        assert_eq!(
            rule.checksum,
            "d2b54f17b9ecdd41d88671fb32276899b322de91fb46ed8e0bac65ad47bb0a0a"
        );
        assert_eq!(rule.severity, RuleSeverity::Notice);
        assert_eq!(rule.category, RuleCategory::CodeStyle);
        assert_eq!(rule.rule_type, RuleType::TreeSitterQuery);
        assert_eq!(rule.language, Language::Python);
        assert_eq!(
            rule.short_description_base64,
            Some("Y2hlY2sgZnVuY3Rpb24gbmFtZXMgZm9yIHdvcmRpbmcgaXNzdWVz".to_string())
        );
        assert_eq!(rule.description_base64, Some("RW5zdXJlIHRoYXQgc29tZSB3b3JkcyBhcmUgbm90IHVzZWQgaW4gdGhlIGNvZGViYXNlIGFuZCBzdWdnZXN0IHJlcGxhY2VtZW50IHdoZW4gYXBwcm9wcmlhdGUuCgpFeGFtcGxlcyBvZiByZXBsYWNlbWVudCBzdWdnZXN0aW9uczoKIC0gYGJsYWNrbGlzdGAgd2l0aCBgZGVueWxpc3RgCiAtIGB3aGl0ZWxpc3RgIHdpdGggYGFsbG93bGlzdGAKIC0gYG1hc3RlcmAgd2l0aCBgcHJpbWFyeWAKIC0gYHNsYXZlYCB3aXRoIGBzZWNvbmRhcnlg".to_string()));
        assert_eq!(rule.code_base64, "LyoqCiAqIEEgdmlzaXQgZnVuY3Rpb24KICogQHBhcmFtIHthbnl9IG5vZGUgQW4gQVNUIGFueSBub2RlLgogKiBAcGFyYW0ge3N0cmluZ30gZmlsZW5hbWUgQSBmaWxlbmFtZSBwYXJhbS4KICogQHBhcmFtIHtzdHJpbmd9IGNvZGUgQSBjb2RlIHBhcmFtLgogKiBAcmV0dXJucwogKi8KZnVuY3Rpb24gdmlzaXQobm9kZSwgZmlsZW5hbWUsIGNvZGUpIHsKICBjb25zdCBGT1JCSURERU5fTkFNRVMgPSBuZXcgTWFwKCk7CgogIEZPUkJJRERFTl9OQU1FUy5zZXQoImJsYWNrbGlzdCIsICJkZW55bGlzdCIpOwogIEZPUkJJRERFTl9OQU1FUy5zZXQoIndoaXRlbGlzdCIsICJhbGxvd2xpc3QiKTsKICBGT1JCSURERU5fTkFNRVMuc2V0KCJtYXN0ZXIiLCAicHJpbWFyeSIpOwogIEZPUkJJRERFTl9OQU1FUy5zZXQoInNsYXZlIiwgInNlY29uZGFyeSIpOwoKICBmdW5jdGlvbiByZXBsYWNlKHRleHQsIHJlcGxhY2VtZW50LCBwb3NpdGlvbkluVGV4dCkgewogICAgdmFyIHJlc3VsdCA9IHRleHQuc3Vic3RyaW5nKDAsIHBvc2l0aW9uSW5UZXh0KTsKICAgIHZhciBwb3MgPSBwb3NpdGlvbkluVGV4dDsKICAgIGZvcih2YXIgaSA9IDA7IGkgPCByZXBsYWNlbWVudC5sZW5ndGg7IGkrKykgewogICAgICAgIHZhciBjID0gdGV4dC5jaGFyQXQocG9zKTsKICAgICAgICBpZihjID49IDY1ICYmIGMgPCA2NSArIDI2KSB7CiAgICAgICAgICAgIHJlc3VsdCArPSByZXBsYWNlbWVudC5jaGFyQXQoaSkudG9VcHBlckNhc2UoKTsKICAgICAgICB9IGVsc2UgewogICAgICAgICAgICByZXN1bHQgKz0gcmVwbGFjZW1lbnQuY2hhckF0KGkpLnRvTG93ZXJDYXNlKCk7CiAgICAgICAgfQogICAgICAgIHBvcyA9IHBvcyArIDE7CiAgICB9CiAgICByZXN1bHQgPSByZXN1bHQgKyB0ZXh0LnN1YnN0cmluZyhwb3MgKyAxLCB0ZXh0Lmxlbmd0aCk7CiAgICByZXR1cm4gcmVzdWx0OwogIH0KCiAgY29uc3QgaGFuZGxlcklkZW50aWZpZXIgPSAoaWRlbnRpZmllcikgPT4gewogICAgY29uc3QgYyA9IGdldENvZGUoaWRlbnRpZmllci5zdGFydCwgaWRlbnRpZmllci5lbmQsIGNvZGUpOwogICAgZm9yIChsZXQgW2tleSwgdmFsdWVdIG9mIEZPUkJJRERFTl9OQU1FUykgewogICAgICBjb25zdCBwb3MgPSBjLnRvTG93ZXJDYXNlKCkuaW5kZXhPZihrZXkpOwogICAgICBpZiAocG9zICE9PSAtMSkgewogICAgICAgIGNvbnN0IG5ld0NvZGUgPSByZXBsYWNlKGMsIHZhbHVlLCBwb3MpOwogICAgICAgIGNvbnN0IGVyciA9IGJ1aWxkRXJyb3IoCiAgICAgICAgICBpZGVudGlmaWVyLnN0YXJ0LmxpbmUsIGlkZW50aWZpZXIuc3RhcnQuY29sLAogICAgICAgICAgaWRlbnRpZmllci5lbmQubGluZSwgaWRlbnRpZmllci5lbmQuY29sLAogICAgICAgICAgYHN0cmluZyAke2tleX0gZGlzY291cmFnZWRgLAogICAgICAgICAgIldBUk5JTkciLAogICAgICAgICAgIkNPREVfU1RZTEUiCiAgICAgICAgKTsKICAgICAgICBjb25zdCBlID0gYnVpbGRFZGl0VXBkYXRlKAogICAgICAgICAgaWRlbnRpZmllci5zdGFydC5saW5lLCBpZGVudGlmaWVyLnN0YXJ0LmNvbCwKICAgICAgICAgIGlkZW50aWZpZXIuZW5kLmxpbmUsIGlkZW50aWZpZXIuZW5kLmNvbCwKICAgICAgICAgIG5ld0NvZGUKICAgICAgICApOwogICAgICAgIGNvbnN0IGYgPSBidWlsZEZpeChgdXNlICR7dmFsdWV9IGluc3RlYWRgLCBbZV0pOwogICAgICAgIGFkZEVycm9yKGVyci5hZGRGaXgoZikpOwogICAgICB9CiAgICB9CiAgfTsKCiAgaGFuZGxlcklkZW50aWZpZXIobm9kZS5jYXB0dXJlc1siZnVuY3Rpb25uYW1lIl0pOwogIGNvbnN0IHBhcmFtZXRlcnMgPSBub2RlLmNhcHR1cmVzWyJwYXJhbWV0ZXJzIl0uY2hpbGRyZW4uZmlsdGVyKGUgPT4gZS5hc3RUeXBlID09PSAiaWRlbnRpZmllciIpOwogIHBhcmFtZXRlcnMuZm9yRWFjaCgoZSkgPT4gewogICAgaGFuZGxlcklkZW50aWZpZXIoZSk7CiAgfSk7Cn0K".to_string());
    }
}
