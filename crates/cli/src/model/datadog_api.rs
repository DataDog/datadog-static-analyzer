use kernel::model::common::Language;
use kernel::model::rule::{Argument, EntityChecked, Rule, RuleCategory, RuleSeverity, RuleType};
use kernel::model::rule_test::RuleTest;
use kernel::model::ruleset::RuleSet;
use secrets::model::secret_rule::{
    SecretRule, SecretRuleMatchValidation, SecretRuleMatchValidationHttp,
    SecretRuleMatchValidationHttpCode, SecretRuleMatchValidationHttpMethod,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// Data for diff-aware scanning
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DiffAwareResponseDataAttributes {
    #[serde(rename = "files")]
    pub files: Vec<String>,
    #[serde(rename = "base_sha")]
    pub base_sha: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DiffAwareResponseData {
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "attributes")]
    pub attributes: DiffAwareResponseDataAttributes,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DiffAwareResponse {
    #[serde(rename = "data")]
    pub data: DiffAwareResponseData,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ConfigResponseDataAttributes {
    #[serde(rename = "config_base64")]
    pub config_base64: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ConfigResponseData {
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "attributes")]
    pub attributes: ConfigResponseDataAttributes,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ConfigResponse {
    #[serde(rename = "data")]
    pub data: ConfigResponseData,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DiffAwareRequestDataAttributes {
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "sha")]
    pub sha: String,
    #[serde(rename = "branch")]
    pub branch: String,
    #[serde(rename = "repository_url")]
    pub repository_url: String,
    #[serde(rename = "config_hash")]
    pub config_hash: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DiffAwareRequestData {
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "type")]
    pub request_type: String,
    #[serde(rename = "attributes")]
    pub attributes: DiffAwareRequestDataAttributes,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DiffAwareRequest {
    #[serde(rename = "data")]
    pub data: DiffAwareRequestData,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ConfigRequestDataAttributes {
    #[serde(rename = "repository")]
    pub repository: String,
    #[serde(rename = "config_base64")]
    pub config_base64: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ConfigRequestData {
    #[serde(rename = "type")]
    pub request_type: String,
    #[serde(rename = "attributes")]
    pub attributes: ConfigRequestDataAttributes,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ConfigRequest {
    #[serde(rename = "data")]
    pub data: ConfigRequestData,
}

/// Data structure to get all attributes and argument for the request.
/// This is used to consolidate all the data we need instead of taking them
/// all one by one.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DiffAwareRequestArguments {
    pub sha: String,
    pub branch: String,
    pub repository_url: String,
    pub config_hash: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DiffAwareData {
    pub base_sha: String,
    pub files: Vec<String>,
}

// Data for the default rules

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ApiDefaultRulesetAttributes {
    #[serde(rename = "rulesets")]
    pub rulesets: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ApiDefaultRuleset {
    pub id: String,
    pub attributes: ApiDefaultRulesetAttributes,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ApiResponseDefaultRuleset {
    pub data: ApiDefaultRuleset,
}

// Data for the rules

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ApiResponseRuleTest {
    pub annotation_count: u32,
    pub filename: String,
    #[serde(rename = "code")]
    pub code_base64: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ApiResponseRule {
    pub name: String,
    pub short_description: Option<String>,
    pub description: Option<String>,
    pub code: String,
    pub language: Language,
    pub tree_sitter_query: Option<String>,
    #[serde(rename = "type")]
    pub rule_type: RuleType,
    pub entity_checked: Option<EntityChecked>,
    pub arguments: Option<Vec<ApiResponseArgument>>,
    pub pattern: Option<String>,
    pub cve: Option<String>,
    pub cwe: Option<String>,
    pub checksum: String,
    pub severity: RuleSeverity,
    pub category: RuleCategory,
    pub tests: Vec<ApiResponseRuleTest>,
    pub is_testing: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ApiResponseArgument {
    pub name: String,
    pub description: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ApiResponseRulesetAttributes {
    pub name: String,
    pub description: String,
    pub rules: Option<Vec<ApiResponseRule>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct APIResponseRuleset {
    pub attributes: ApiResponseRulesetAttributes,
}

impl APIResponseRuleset {
    fn into_ruleset(self) -> RuleSet {
        let ruleset_name = self.attributes.name;
        let description = self.attributes.description;
        let rules = match self.attributes.rules {
            Some(r) => r
                .into_iter()
                .map(|rule_from_api| Rule {
                    name: format!("{}/{}", ruleset_name, rule_from_api.name),
                    description_base64: rule_from_api.description,
                    short_description_base64: rule_from_api.short_description,
                    language: rule_from_api.language,
                    rule_type: rule_from_api.rule_type,
                    checksum: rule_from_api.checksum,
                    entity_checked: rule_from_api.entity_checked,
                    code_base64: rule_from_api.code,
                    category: rule_from_api.category,
                    cwe: rule_from_api.cwe,
                    severity: rule_from_api.severity,
                    pattern: rule_from_api.pattern,
                    tree_sitter_query_base64: rule_from_api.tree_sitter_query,
                    arguments: rule_from_api
                        .arguments
                        .unwrap_or_default()
                        .into_iter()
                        .map(|a| Argument {
                            name_base64: a.name,
                            description_base64: a.description,
                        })
                        .collect(),
                    tests: rule_from_api
                        .tests
                        .into_iter()
                        .map(|t| RuleTest {
                            code_base64: t.code_base64,
                            filename: t.filename,
                            annotation_count: t.annotation_count,
                        })
                        .collect(),
                    is_testing: rule_from_api.is_testing,
                })
                .collect(),
            None => Vec::new(),
        };
        RuleSet {
            rules,
            description: Some(description),
            name: ruleset_name,
        }
    }
}

#[derive(Deserialize, Clone)]
pub struct StaticAnalysisRulesAPIResponse {
    pub data: APIResponseRuleset,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SecretRuleApiMatchValidationHttpCode {
    pub start: u16,
    pub end: u16,
}

impl From<&SecretRuleApiMatchValidationHttpCode> for SecretRuleMatchValidationHttpCode {
    fn from(value: &SecretRuleApiMatchValidationHttpCode) -> Self {
        SecretRuleMatchValidationHttpCode {
            start: value.start,
            end: value.end,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, Eq, PartialEq, Hash)]
#[serde(rename_all = "UPPERCASE")]
pub enum SecretRuleApiMatchValidationHttpMethod {
    Get,
    Post,
    Patch,
    Put,
    Delete,
}

impl From<SecretRuleApiMatchValidationHttpMethod> for SecretRuleMatchValidationHttpMethod {
    fn from(val: SecretRuleApiMatchValidationHttpMethod) -> Self {
        match val {
            SecretRuleApiMatchValidationHttpMethod::Get => SecretRuleMatchValidationHttpMethod::Get,
            SecretRuleApiMatchValidationHttpMethod::Post => {
                SecretRuleMatchValidationHttpMethod::Post
            }
            SecretRuleApiMatchValidationHttpMethod::Put => SecretRuleMatchValidationHttpMethod::Put,
            SecretRuleApiMatchValidationHttpMethod::Patch => {
                SecretRuleMatchValidationHttpMethod::Patch
            }
            SecretRuleApiMatchValidationHttpMethod::Delete => {
                SecretRuleMatchValidationHttpMethod::Delete
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SecretRuleApiMatchValidation {
    #[serde(rename = "type")]
    pub r#type: String,
    pub endpoint: Option<String>,
    pub hosts: Option<Vec<String>>,
    pub request_headers: Option<HashMap<String, String>>,
    pub http_method: Option<SecretRuleApiMatchValidationHttpMethod>,
    pub timeout_seconds: Option<u64>,
    pub valid_http_status_code: Option<Vec<SecretRuleApiMatchValidationHttpCode>>,
    pub invalid_http_status_code: Option<Vec<SecretRuleApiMatchValidationHttpCode>>,
}

impl SecretRuleApiMatchValidation {
    const AWS_ID_STRING: &'static str = "AwsId";
    const AWS_SECRET_STRING: &'static str = "AwsSecret";
    const AWS_SESSION_STRING: &'static str = "AwsSession";
    const CUSTOM_HTTP_STRING: &'static str = "CustomHttp";
}

impl TryFrom<SecretRuleApiMatchValidation> for SecretRuleMatchValidation {
    type Error = &'static str;

    fn try_from(value: SecretRuleApiMatchValidation) -> Result<Self, Self::Error> {
        match value.r#type.as_str() {
            SecretRuleApiMatchValidation::AWS_SECRET_STRING => {
                Ok(SecretRuleMatchValidation::AwsSecret)
            }
            SecretRuleApiMatchValidation::AWS_ID_STRING => Ok(SecretRuleMatchValidation::AwsId),
            SecretRuleApiMatchValidation::AWS_SESSION_STRING => {
                Ok(SecretRuleMatchValidation::AwsSession)
            }
            SecretRuleApiMatchValidation::CUSTOM_HTTP_STRING => Ok(
                SecretRuleMatchValidation::CustomHttp(SecretRuleMatchValidationHttp {
                    endpoint: value.endpoint.expect("no endpoint"),
                    hosts: value.hosts.unwrap_or_default(),
                    request_headers: value.request_headers.unwrap_or_default(),
                    http_method: value.http_method.expect("missing http method").into(),
                    timeout_seconds: value.timeout_seconds,
                    valid_http_status_code: value
                        .valid_http_status_code
                        .unwrap_or_default()
                        .iter()
                        .map(|v| v.into())
                        .collect(),
                    invalid_http_status_code: value
                        .invalid_http_status_code
                        .unwrap_or_default()
                        .iter()
                        .map(|v| v.into())
                        .collect(),
                }),
            ),
            _ => Err("invalid match validation type"),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SecretRuleApiAttributes {
    pub name: String,
    pub description: String,
    pub pattern: String,
    pub default_included_keywords: Option<Vec<String>>,
    pub validators: Option<Vec<String>>,
    pub match_validation: Option<SecretRuleApiMatchValidation>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SecretRuleApiType {
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "attributes")]
    pub attributes: SecretRuleApiAttributes,
}

impl TryFrom<SecretRuleApiType> for SecretRule {
    type Error = &'static str;

    fn try_from(val: SecretRuleApiType) -> Result<Self, Self::Error> {
        if let Some(match_validation) = val.attributes.match_validation {
            match <SecretRuleApiMatchValidation as TryInto<SecretRuleMatchValidation>>::try_into(
                match_validation,
            ) {
                Ok(validation) => Ok(SecretRule {
                    id: val.id,
                    name: val.attributes.name,
                    description: val.attributes.description,
                    pattern: val.attributes.pattern,
                    default_included_keywords: val
                        .attributes
                        .default_included_keywords
                        .unwrap_or_default(),
                    validators: val.attributes.validators,
                    match_validation: Some(validation),
                }),
                Err(s) => Err(s),
            }
        } else {
            Ok(SecretRule {
                id: val.id,
                name: val.attributes.name,
                description: val.attributes.description,
                pattern: val.attributes.pattern,
                default_included_keywords: val
                    .attributes
                    .default_included_keywords
                    .unwrap_or_default(),
                validators: val.attributes.validators,
                match_validation: None,
            })
        }
    }
}

#[derive(Deserialize, Clone)]
pub struct StaticAnalysisSecretsAPIResponse {
    pub data: Vec<SecretRuleApiType>,
}

#[derive(Deserialize)]
pub struct APIErrorResponse {
    pub errors: Vec<APIError>,
}

#[derive(Deserialize)]
pub struct APIError {
    pub title: String,
    pub status: Option<String>,
    pub detail: Option<String>,
}

impl StaticAnalysisRulesAPIResponse {
    pub fn into_ruleset(self) -> RuleSet {
        self.data.into_ruleset()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::datadog_api::SecretRuleApiMatchValidationHttpMethod::Get;
    use kernel::model::{
        common::Language,
        rule::{RuleCategory, RuleSeverity, RuleType},
    };
    use serde_json::json;

    // correctly map all the data from the API
    #[test]
    fn parse_config_file_with_rulesets_and_ignore_paths() {
        let data = json!(
        {
            "data": {
                "id": "python-inclusive",
                "type": "rulesets",
                "attributes": {
                    "description": "UnVsZXMgZm9yIFB5dGhvbiB0byBhdm9pZCBpbmFwcHJvcHJpYXRlIHdvcmRpbmcgaW4gdGhlIGNvZGUgYW5kIGNvbW1lbnRzLg==",
                    "name": "python-inclusive",
                    "rules": [
                        {
                            "id": "function-definition",
                            "name": "function-definition",
                            "short_description": "Y2hlY2sgZnVuY3Rpb24gbmFtZXMgZm9yIHdvcmRpbmcgaXNzdWVz",
                            "description": "RW5zdXJlIHRoYXQgc29tZSB3b3JkcyBhcmUgbm90IHVzZWQgaW4gdGhlIGNvZGViYXNlIGFuZCBzdWdnZXN0IHJlcGxhY2VtZW50IHdoZW4gYXBwcm9wcmlhdGUuCgpFeGFtcGxlcyBvZiByZXBsYWNlbWVudCBzdWdnZXN0aW9uczoKIC0gYGJsYWNrbGlzdGAgd2l0aCBgZGVueWxpc3RgCiAtIGB3aGl0ZWxpc3RgIHdpdGggYGFsbG93bGlzdGAKIC0gYG1hc3RlcmAgd2l0aCBgcHJpbWFyeWAKIC0gYHNsYXZlYCB3aXRoIGBzZWNvbmRhcnlg",
                            "code": "LyoqCiAqIEEgdmlzaXQgZnVuY3Rpb24KICogQHBhcmFtIHthbnl9IG5vZGUgQW4gQVNUIGFueSBub2RlLgogKiBAcGFyYW0ge3N0cmluZ30gZmlsZW5hbWUgQSBmaWxlbmFtZSBwYXJhbS4KICogQHBhcmFtIHtzdHJpbmd9IGNvZGUgQSBjb2RlIHBhcmFtLgogKiBAcmV0dXJucwogKi8KZnVuY3Rpb24gdmlzaXQobm9kZSwgZmlsZW5hbWUsIGNvZGUpIHsKICBjb25zdCBGT1JCSURERU5fTkFNRVMgPSBuZXcgTWFwKCk7CgogIEZPUkJJRERFTl9OQU1FUy5zZXQoImJsYWNrbGlzdCIsICJkZW55bGlzdCIpOwogIEZPUkJJRERFTl9OQU1FUy5zZXQoIndoaXRlbGlzdCIsICJhbGxvd2xpc3QiKTsKICBGT1JCSURERU5fTkFNRVMuc2V0KCJtYXN0ZXIiLCAicHJpbWFyeSIpOwogIEZPUkJJRERFTl9OQU1FUy5zZXQoInNsYXZlIiwgInNlY29uZGFyeSIpOwoKICBmdW5jdGlvbiByZXBsYWNlKHRleHQsIHJlcGxhY2VtZW50LCBwb3NpdGlvbkluVGV4dCkgewogICAgdmFyIHJlc3VsdCA9IHRleHQuc3Vic3RyaW5nKDAsIHBvc2l0aW9uSW5UZXh0KTsKICAgIHZhciBwb3MgPSBwb3NpdGlvbkluVGV4dDsKICAgIGZvcih2YXIgaSA9IDA7IGkgPCByZXBsYWNlbWVudC5sZW5ndGg7IGkrKykgewogICAgICAgIHZhciBjID0gdGV4dC5jaGFyQXQocG9zKTsKICAgICAgICBpZihjID49IDY1ICYmIGMgPCA2NSArIDI2KSB7CiAgICAgICAgICAgIHJlc3VsdCArPSByZXBsYWNlbWVudC5jaGFyQXQoaSkudG9VcHBlckNhc2UoKTsKICAgICAgICB9IGVsc2UgewogICAgICAgICAgICByZXN1bHQgKz0gcmVwbGFjZW1lbnQuY2hhckF0KGkpLnRvTG93ZXJDYXNlKCk7CiAgICAgICAgfQogICAgICAgIHBvcyA9IHBvcyArIDE7CiAgICB9CiAgICByZXN1bHQgPSByZXN1bHQgKyB0ZXh0LnN1YnN0cmluZyhwb3MgKyAxLCB0ZXh0Lmxlbmd0aCk7CiAgICByZXR1cm4gcmVzdWx0OwogIH0KCiAgY29uc3QgaGFuZGxlcklkZW50aWZpZXIgPSAoaWRlbnRpZmllcikgPT4gewogICAgY29uc3QgYyA9IGdldENvZGUoaWRlbnRpZmllci5zdGFydCwgaWRlbnRpZmllci5lbmQsIGNvZGUpOwogICAgZm9yIChsZXQgW2tleSwgdmFsdWVdIG9mIEZPUkJJRERFTl9OQU1FUykgewogICAgICBjb25zdCBwb3MgPSBjLnRvTG93ZXJDYXNlKCkuaW5kZXhPZihrZXkpOwogICAgICBpZiAocG9zICE9PSAtMSkgewogICAgICAgIGNvbnN0IG5ld0NvZGUgPSByZXBsYWNlKGMsIHZhbHVlLCBwb3MpOwogICAgICAgIGNvbnN0IGVyciA9IGJ1aWxkRXJyb3IoCiAgICAgICAgICBpZGVudGlmaWVyLnN0YXJ0LmxpbmUsIGlkZW50aWZpZXIuc3RhcnQuY29sLAogICAgICAgICAgaWRlbnRpZmllci5lbmQubGluZSwgaWRlbnRpZmllci5lbmQuY29sLAogICAgICAgICAgYHN0cmluZyAke2tleX0gZGlzY291cmFnZWRgLAogICAgICAgICAgIldBUk5JTkciLAogICAgICAgICAgIkNPREVfU1RZTEUiCiAgICAgICAgKTsKICAgICAgICBjb25zdCBlID0gYnVpbGRFZGl0VXBkYXRlKAogICAgICAgICAgaWRlbnRpZmllci5zdGFydC5saW5lLCBpZGVudGlmaWVyLnN0YXJ0LmNvbCwKICAgICAgICAgIGlkZW50aWZpZXIuZW5kLmxpbmUsIGlkZW50aWZpZXIuZW5kLmNvbCwKICAgICAgICAgIG5ld0NvZGUKICAgICAgICApOwogICAgICAgIGNvbnN0IGYgPSBidWlsZEZpeChgdXNlICR7dmFsdWV9IGluc3RlYWRgLCBbZV0pOwogICAgICAgIGFkZEVycm9yKGVyci5hZGRGaXgoZikpOwogICAgICB9CiAgICB9CiAgfTsKCiAgaGFuZGxlcklkZW50aWZpZXIobm9kZS5jYXB0dXJlc1siZnVuY3Rpb25uYW1lIl0pOwogIGNvbnN0IHBhcmFtZXRlcnMgPSBub2RlLmNhcHR1cmVzWyJwYXJhbWV0ZXJzIl0uY2hpbGRyZW4uZmlsdGVyKGUgPT4gZS5hc3RUeXBlID09PSAiaWRlbnRpZmllciIpOwogIHBhcmFtZXRlcnMuZm9yRWFjaCgoZSkgPT4gewogICAgaGFuZGxlcklkZW50aWZpZXIoZSk7CiAgfSk7Cn0K",
                            "language": "PYTHON",
                            "type": "TREE_SITTER_QUERY",
                            "tree_sitter_query": "KGZ1bmN0aW9uX2RlZmluaXRpb24KICAgbmFtZTogKGlkZW50aWZpZXIpIEBmdW5jdGlvbm5hbWUKICAgcGFyYW1ldGVyczogKHBhcmFtZXRlcnMpIEBwYXJhbWV0ZXJzCik=",
                            "cve": "",
                            "cwe": "",
                            "checksum": "d2b54f17b9ecdd41d88671fb32276899b322de91fb46ed8e0bac65ad47bb0a0a",
                            "created_at": "0001-01-01T00:00:00Z",
                            "created_by": "",
                            "last_updated_at": "2023-06-16T16:23:42.315054843Z",
                            "last_updated_by": "julien.delange",
                            "severity": "NOTICE",
                            "category": "CODE_STYLE",
                            "tests": [
                                {
                                    "filename": "compliant.py",
                                    "code": "ZGVmIGZvb19kZW55bGlzdCgpOgogICAgcGFzcw==",
                                    "annotation_count": 0
                                }
                            ],
                            "is_published": false,
                            "is_testing": false
                        }
                    ]
                }
            }
        });
        let res = serde_json::from_value::<StaticAnalysisRulesAPIResponse>(data);
        let ruleset = res.unwrap().into_ruleset();
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

    // if the rules is `null`, we still get 0 rules and the program does not crash.
    #[test]
    fn parse_config_file_with_rulesets_and_rules_null() {
        let data = json!(
        {
            "data": {
                "id": "python-inclusive",
                "type": "rulesets",
                "attributes": {
                    "description": "UnVsZXMgZm9yIFB5dGhvbiB0byBhdm9pZCBpbmFwcHJvcHJpYXRlIHdvcmRpbmcgaW4gdGhlIGNvZGUgYW5kIGNvbW1lbnRzLg==",
                    "name": "python-inclusive",
                    "rules": null
                }
            }
        });
        let res = serde_json::from_value::<StaticAnalysisRulesAPIResponse>(data);
        let ruleset = res.unwrap().into_ruleset();
        assert_eq!(0, ruleset.rules.len());
    }

    #[test]
    fn convert_secrets_rules_from_api_to_lib_invalid_match_validation_type() {
        let api_secret_rule_invalid_match_validation_type = SecretRuleApiType {
            id: "secret_type".to_string(),
            attributes: SecretRuleApiAttributes {
                name: "secret_rule_name".to_string(),
                description: "secret_rule_description".to_string(),
                pattern: "pattern".to_string(),
                default_included_keywords: None,
                validators: None,
                match_validation: Some(SecretRuleApiMatchValidation {
                    r#type: "foo".to_string(),
                    endpoint: None,
                    hosts: None,
                    request_headers: None,
                    http_method: None,
                    timeout_seconds: None,
                    valid_http_status_code: None,
                    invalid_http_status_code: None,
                }),
            },
        };
        let converted = <SecretRuleApiType as TryInto<SecretRule>>::try_into(
            api_secret_rule_invalid_match_validation_type,
        );
        assert!(converted.is_err());
        assert_eq!(converted.unwrap_err(), "invalid match validation type")
    }

    #[test]
    fn convert_secrets_rules_from_api_to_lib_success() {
        let api_secret_rule_invalid_match_validation_type = SecretRuleApiType {
            id: "secret_type".to_string(),
            attributes: SecretRuleApiAttributes {
                name: "secret_rule_name".to_string(),
                description: "secret_rule_description".to_string(),
                pattern: "pattern".to_string(),
                default_included_keywords: None,
                validators: None,
                match_validation: Some(SecretRuleApiMatchValidation {
                    r#type: SecretRuleApiMatchValidation::CUSTOM_HTTP_STRING.to_string(),
                    endpoint: Some("endpoint".to_string()),
                    hosts: Some(vec!["endpoint".to_string()]),
                    request_headers: None,
                    http_method: Some(Get),
                    timeout_seconds: None,
                    valid_http_status_code: None,
                    invalid_http_status_code: None,
                }),
            },
        };
        let converted = <SecretRuleApiType as TryInto<SecretRule>>::try_into(
            api_secret_rule_invalid_match_validation_type,
        );
        assert!(converted.is_ok());
    }

    #[test]
    fn convert_secrets_rules_from_api_to_lib_aws_secret() {
        let api_secret_rule_invalid_match_validation_type = SecretRuleApiType {
            id: "secret_type".to_string(),
            attributes: SecretRuleApiAttributes {
                name: "secret_rule_name".to_string(),
                description: "secret_rule_description".to_string(),
                pattern: "pattern".to_string(),
                default_included_keywords: None,
                validators: None,
                match_validation: Some(SecretRuleApiMatchValidation {
                    r#type: SecretRuleApiMatchValidation::AWS_SECRET_STRING.to_string(),
                    endpoint: None,
                    hosts: None,
                    request_headers: None,
                    http_method: None,
                    timeout_seconds: None,
                    valid_http_status_code: None,
                    invalid_http_status_code: None,
                }),
            },
        };
        let converted = <SecretRuleApiType as TryInto<SecretRule>>::try_into(
            api_secret_rule_invalid_match_validation_type,
        );
        assert_eq!(
            converted
                .expect("get converted value")
                .match_validation
                .unwrap(),
            SecretRuleMatchValidation::AwsSecret
        );
    }

    #[test]
    fn convert_secrets_rules_from_api_to_lib_aws_id() {
        let api_secret_rule_invalid_match_validation_type = SecretRuleApiType {
            id: "secret_type".to_string(),
            attributes: SecretRuleApiAttributes {
                name: "secret_rule_name".to_string(),
                description: "secret_rule_description".to_string(),
                pattern: "pattern".to_string(),
                default_included_keywords: None,
                validators: None,
                match_validation: Some(SecretRuleApiMatchValidation {
                    r#type: SecretRuleApiMatchValidation::AWS_ID_STRING.to_string(),
                    endpoint: None,
                    hosts: None,
                    request_headers: None,
                    http_method: None,
                    timeout_seconds: None,
                    valid_http_status_code: None,
                    invalid_http_status_code: None,
                }),
            },
        };
        let converted = <SecretRuleApiType as TryInto<SecretRule>>::try_into(
            api_secret_rule_invalid_match_validation_type,
        );
        assert_eq!(
            converted
                .expect("get converted value")
                .match_validation
                .unwrap(),
            SecretRuleMatchValidation::AwsId
        );
    }

    #[test]
    fn convert_secrets_rules_from_api_to_lib_aws_session() {
        let api_secret_rule_invalid_match_validation_type = SecretRuleApiType {
            id: "secret_type".to_string(),
            attributes: SecretRuleApiAttributes {
                name: "secret_rule_name".to_string(),
                description: "secret_rule_description".to_string(),
                pattern: "pattern".to_string(),
                default_included_keywords: None,
                validators: None,
                match_validation: Some(SecretRuleApiMatchValidation {
                    r#type: SecretRuleApiMatchValidation::AWS_SESSION_STRING.to_string(),
                    endpoint: None,
                    hosts: None,
                    request_headers: None,
                    http_method: None,
                    timeout_seconds: None,
                    valid_http_status_code: None,
                    invalid_http_status_code: None,
                }),
            },
        };
        let converted = <SecretRuleApiType as TryInto<SecretRule>>::try_into(
            api_secret_rule_invalid_match_validation_type,
        );
        assert_eq!(
            converted
                .expect("get converted value")
                .match_validation
                .unwrap(),
            SecretRuleMatchValidation::AwsSession
        );
    }
}
