// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::model::secret_rule::SecretRuleMatchValidation::CustomHttp;
use common::model::diff_aware::DiffAware;
use dd_sds::SecondaryValidator;
use dd_sds::{
    AwsConfig, AwsType, BodyMatcher, CustomHttpConfig, CustomHttpConfigV2, HttpCallConfig,
    HttpMethod, HttpRequestConfig, HttpResponseConfig, HttpStatusCodeRange,
    JwtClaimsValidatorConfig, MatchAction, MatchPairingConfig, MatchValidationType,
    PairedValidatorConfig, ProximityKeywordsConfig, RegexRuleConfig, ResponseCondition,
    ResponseConditionType, RootRuleConfig, StatusCodeMatcher, TemplatedMatchString,
};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::collections::HashSet;
use std::fmt;
use strum::IntoEnumIterator;

const DEFAULT_LOOK_AHEAD_CHARACTER_COUNT: usize = 30;

lazy_static! {
    /// Set of all valid secondary validator names, computed once at initialization.
    static ref ALLOWED_VALIDATORS: HashSet<String> = {
        SecondaryValidator::iter()
            .map(|v| v.as_ref().to_string())
            .collect()
    };
}

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct SecretRuleMatchValidationHttpCode {
    pub start: u16,
    pub end: u16,
}

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq, Copy)]
#[serde(rename_all = "UPPERCASE")]
pub enum SecretRuleMatchValidationHttpMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

#[derive(Copy, Clone, Deserialize, Debug, Serialize, Eq, PartialEq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum RulePriority {
    Info,
    Low,
    Medium,
    High,
    Critical,
    None,
}

impl TryFrom<&str> for RulePriority {
    type Error = &'static str;

    fn try_from(s: &str) -> Result<Self, &'static str> {
        match s.to_lowercase().as_str() {
            "none" => Ok(RulePriority::Info),
            "info" => Ok(RulePriority::Info),
            "low" => Ok(RulePriority::Low),
            "medium" => Ok(RulePriority::Medium),
            "high" => Ok(RulePriority::High),
            "critical" => Ok(RulePriority::Critical),
            _ => Err("unknown priority"),
        }
    }
}

impl fmt::Display for RulePriority {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let text = match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
            Self::None => "none",
        };
        write!(f, "{text}")
    }
}

impl From<SecretRuleMatchValidationHttpMethod> for HttpMethod {
    fn from(value: SecretRuleMatchValidationHttpMethod) -> Self {
        match value {
            SecretRuleMatchValidationHttpMethod::Get => HttpMethod::Get,
            SecretRuleMatchValidationHttpMethod::Post => HttpMethod::Post,
            SecretRuleMatchValidationHttpMethod::Put => HttpMethod::Put,
            SecretRuleMatchValidationHttpMethod::Patch => HttpMethod::Patch,
            SecretRuleMatchValidationHttpMethod::Delete => HttpMethod::Delete,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub enum SecretRuleMatchValidation {
    AwsId,
    AwsSecret,
    AwsSession,
    CustomHttp(SecretRuleMatchValidationHttp),
    CustomHttpV2(SecretRuleMatchValidationHttpV2),
}

impl TryFrom<&SecretRuleMatchValidation> for MatchValidationType {
    type Error = &'static str;

    fn try_from(value: &SecretRuleMatchValidation) -> Result<Self, Self::Error> {
        match value {
            SecretRuleMatchValidation::AwsId => Ok(MatchValidationType::Aws(AwsType::AwsId)),
            SecretRuleMatchValidation::AwsSecret => Ok(MatchValidationType::Aws(
                AwsType::AwsSecret(AwsConfig::default()),
            )),
            SecretRuleMatchValidation::AwsSession => {
                Ok(MatchValidationType::Aws(AwsType::AwsSession))
            }
            CustomHttp(custom_http) => {
                let invalid_ports: Vec<HttpStatusCodeRange> = custom_http
                    .invalid_http_status_code
                    .iter()
                    .map(|v| HttpStatusCodeRange {
                        start: v.start,
                        end: v.end,
                    })
                    .collect();
                let valid_ports: Vec<HttpStatusCodeRange> = custom_http
                    .valid_http_status_code
                    .iter()
                    .map(|v| HttpStatusCodeRange {
                        start: v.start,
                        end: v.end,
                    })
                    .collect();
                Ok(MatchValidationType::CustomHttp(CustomHttpConfig {
                    endpoint: custom_http.endpoint.clone(),
                    hosts: custom_http.hosts.clone(),
                    http_method: custom_http.http_method.into(),
                    request_headers: custom_http.request_headers.clone(),
                    valid_http_status_code: valid_ports,
                    invalid_http_status_code: invalid_ports,
                    timeout_seconds: custom_http.timeout_seconds.unwrap() as u32,
                }))
            }
            SecretRuleMatchValidation::CustomHttpV2(custom_http_v2) => {
                // Convert match pairing config
                let match_pairing =
                    custom_http_v2
                        .match_pairing
                        .as_ref()
                        .map(|mp| MatchPairingConfig {
                            kind: mp.kind.clone(),
                            parameters: mp.parameters.clone(),
                        });

                // Convert HTTP calls
                let calls: Vec<HttpCallConfig> = custom_http_v2
                    .calls
                    .iter()
                    .map(|call| {
                        // Convert request config
                        let timeout_seconds = call.request.timeout_seconds.unwrap_or(3);
                        let request = HttpRequestConfig {
                            endpoint: TemplatedMatchString(call.request.endpoint.clone()),
                            method: call.request.method.into(),
                            hosts: call
                                .request
                                .hosts
                                .iter()
                                .map(|h| TemplatedMatchString(h.clone()))
                                .collect(),
                            headers: call
                                .request
                                .headers
                                .iter()
                                .map(|(k, v)| (k.clone(), TemplatedMatchString(v.clone())))
                                .collect(),
                            body: call
                                .request
                                .body
                                .as_ref()
                                .map(|body| TemplatedMatchString(body.clone())),
                            timeout: std::time::Duration::from_secs(timeout_seconds),
                        };

                        // Convert response config
                        let conditions: Vec<ResponseCondition> = call
                            .response
                            .conditions
                            .iter()
                            .map(|cond| {
                                // Convert status code matcher
                                let status_code =
                                    cond.status_code.as_ref().map(|matcher| match matcher {
                                        SecretRuleStatusCodeMatcher::Single { single } => {
                                            StatusCodeMatcher::Single(*single)
                                        }
                                        SecretRuleStatusCodeMatcher::List { list } => {
                                            StatusCodeMatcher::List(list.clone())
                                        }
                                        SecretRuleStatusCodeMatcher::Range { range } => {
                                            StatusCodeMatcher::Range {
                                                start: range.start,
                                                end: range.end,
                                            }
                                        }
                                    });

                                // Convert raw body matcher
                                let raw_body =
                                    cond.raw_body.as_ref().map(|matcher| match matcher {
                                        SecretRuleBodyMatcher::ExactMatch { exact_match } => {
                                            BodyMatcher::ExactMatch(exact_match.clone())
                                        }
                                        SecretRuleBodyMatcher::Regex { regex } => {
                                            BodyMatcher::Regex(regex.clone())
                                        }
                                        SecretRuleBodyMatcher::Present { .. } => {
                                            BodyMatcher::Present
                                        }
                                    });

                                // Convert body matchers
                                let body = cond.body.as_ref().map(|body_map| {
                                    body_map
                                        .iter()
                                        .map(|(k, v)| {
                                            let matcher = match v {
                                                SecretRuleBodyMatcher::ExactMatch {
                                                    exact_match,
                                                } => BodyMatcher::ExactMatch(exact_match.clone()),
                                                SecretRuleBodyMatcher::Regex { regex } => {
                                                    BodyMatcher::Regex(regex.clone())
                                                }
                                                SecretRuleBodyMatcher::Present { .. } => {
                                                    BodyMatcher::Present
                                                }
                                            };
                                            (k.clone(), matcher)
                                        })
                                        .collect()
                                });

                                ResponseCondition {
                                    condition_type: match cond.condition_type {
                                        SecretRuleResponseConditionType::Valid => {
                                            ResponseConditionType::Valid
                                        }
                                        SecretRuleResponseConditionType::Invalid => {
                                            ResponseConditionType::Invalid
                                        }
                                    },
                                    status_code,
                                    raw_body,
                                    body,
                                }
                            })
                            .collect();

                        let response = HttpResponseConfig { conditions };

                        HttpCallConfig { request, response }
                    })
                    .collect();

                // Convert provides
                let provides: Vec<PairedValidatorConfig> = custom_http_v2
                    .provides
                    .iter()
                    .map(|p| PairedValidatorConfig {
                        kind: p.kind.clone(),
                        name: p.name.clone(),
                    })
                    .collect();

                Ok(MatchValidationType::CustomHttpV2(CustomHttpConfigV2 {
                    match_pairing,
                    calls,
                    provides: Some(provides),
                }))
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct SecretRuleMatchValidationHttp {
    pub endpoint: String,
    pub hosts: Vec<String>,
    pub request_headers: BTreeMap<String, String>,
    pub http_method: SecretRuleMatchValidationHttpMethod,
    pub timeout_seconds: Option<u64>,
    pub valid_http_status_code: Vec<SecretRuleMatchValidationHttpCode>,
    pub invalid_http_status_code: Vec<SecretRuleMatchValidationHttpCode>,
}

// V2 Structs for Online Validation V2

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct SecretRuleMatchValidationHttpV2 {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub match_pairing: Option<SecretRuleMatchPairingConfig>,
    pub calls: Vec<SecretRuleHttpCallConfig>,
    pub provides: Vec<SecretRulePairedValidatorConfig>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct SecretRuleMatchPairingConfig {
    pub kind: String,
    pub parameters: BTreeMap<String, String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct SecretRuleHttpCallConfig {
    pub request: SecretRuleHttpRequestConfig,
    pub response: SecretRuleHttpResponseConfig,
}

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct SecretRuleHttpRequestConfig {
    pub endpoint: String,
    #[serde(default = "default_http_method_v2")]
    pub method: SecretRuleMatchValidationHttpMethod,
    #[serde(default)]
    pub hosts: Vec<String>,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_seconds: Option<u64>,
}

fn default_http_method_v2() -> SecretRuleMatchValidationHttpMethod {
    SecretRuleMatchValidationHttpMethod::Get
}

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct SecretRuleHttpResponseConfig {
    pub conditions: Vec<SecretRuleResponseCondition>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct SecretRuleResponseCondition {
    pub condition_type: SecretRuleResponseConditionType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_code: Option<SecretRuleStatusCodeMatcher>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_body: Option<SecretRuleBodyMatcher>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<BTreeMap<String, SecretRuleBodyMatcher>>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq, Copy)]
pub enum SecretRuleResponseConditionType {
    Valid,
    Invalid,
}

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
#[serde(untagged)]
pub enum SecretRuleStatusCodeMatcher {
    Single { single: u16 },
    List { list: Vec<u16> },
    Range { range: SecretRuleStatusCodeRange },
}

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct SecretRuleStatusCodeRange {
    pub start: u16,
    pub end: u16,
}

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
#[serde(untagged)]
pub enum SecretRuleBodyMatcher {
    ExactMatch { exact_match: String },
    Regex { regex: String },
    Present { present: bool },
}

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct SecretRulePairedValidatorConfig {
    pub kind: String,
    pub name: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct SecretRuleValidator {
    #[serde(rename = "type")]
    pub type_: String,
    pub config: Option<serde_json::Value>,
}

impl SecretRuleValidator {
    /// Convert the validator and its configuration to a SecondaryValidator that can be used with RegexRuleConfig.
    /// Returns the validator if successful, or an error message if the validator type or configuration is invalid.
    pub fn try_to_secondary_validator(&self, use_debug: bool) -> Option<SecondaryValidator> {
        // Check if the validator type is valid
        if !ALLOWED_VALIDATORS.contains(&self.type_) {
            if use_debug {
                eprintln!("invalid validator type: {}", self.type_);
            }
            return None;
        }

        // Find the matching SecondaryValidator enum variant
        let base_validator = SecondaryValidator::iter()
            .find(|val| val.as_ref() == self.type_)
            .expect("validator should exist");

        // If there's a config, we need to handle it based on the validator type
        if let Some(config_value) = &self.config {
            match self.type_.as_str() {
                "JwtClaimsValidator" => {
                    // Deserialize the config into JwtClaimsValidatorConfig
                    match serde_json::from_value::<JwtClaimsValidatorConfig>(config_value.clone()) {
                        Ok(jwt_config) => {
                            // Create a JwtClaimsValidator with the config
                            Some(SecondaryValidator::JwtClaimsValidator { config: jwt_config })
                        }
                        Err(e) => {
                            if use_debug {
                                eprintln!("failed to deserialize JwtClaimsValidator config: {}", e);
                            }
                            None
                        }
                    }
                }
                // Add other validator types with configurations as needed
                _ => {
                    // Unknown validator type with config - drop it since it will fail in dd_sds
                    if use_debug {
                        eprintln!(
                            "validator {} has configuration but is not supported, dropping validator",
                            self.type_
                        );
                    }
                    None
                }
            }
        } else {
            // No config provided, use the base validator
            Some(base_validator)
        }
    }
}

// This is the secret rule exposed by SDS
#[derive(Clone, Deserialize, Debug, Serialize, Eq, PartialEq)]
pub struct SecretRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub pattern: String,
    pub priority: RulePriority,
    pub default_included_keywords: Vec<String>,
    pub default_excluded_keywords: Vec<String>,
    pub look_ahead_character_count: Option<usize>,
    pub validators: Option<Vec<String>>,
    pub validators_v2: Option<Vec<SecretRuleValidator>>,
    pub match_validation: Option<SecretRuleMatchValidation>,
    pub sds_id: String,
    pub pattern_capture_groups: Vec<String>,
}

impl SecretRule {
    /// Convert the rule into a configuration usable by SDS.
    pub fn convert_to_sds_ruleconfig(&self, use_debug: bool) -> RootRuleConfig<RegexRuleConfig> {
        let mut regex_rule_config = RegexRuleConfig::new(&self.pattern);

        if !self.default_included_keywords.is_empty() {
            regex_rule_config =
                regex_rule_config.with_proximity_keywords(ProximityKeywordsConfig {
                    look_ahead_character_count: self
                        .look_ahead_character_count
                        .unwrap_or(DEFAULT_LOOK_AHEAD_CHARACTER_COUNT),
                    included_keywords: self.default_included_keywords.clone(),
                    excluded_keywords: self.default_excluded_keywords.clone(),
                });
        }

        // Handle validators_v2 (with configuration support) if present, otherwise fall back to validators
        if let Some(validators_v2) = &self.validators_v2 {
            for validator_config in validators_v2 {
                if let Some(validator) = validator_config.try_to_secondary_validator(use_debug) {
                    regex_rule_config = regex_rule_config.with_validator(Some(validator));
                }
            }
        } else if let Some(validators) = &self.validators {
            // TODO: Deprecate in favor of validators_v2
            // Legacy validators without configuration
            for v in validators {
                // Skip JwtClaimsValidator in v1 path - it requires configuration only available in v2
                if v == "JwtClaimsValidator" {
                    if use_debug {
                        eprintln!(
                            "JwtClaimsValidator requires validators_v2 with config, skipping"
                        );
                    }
                    continue;
                }

                if ALLOWED_VALIDATORS.contains(v) {
                    // Safe because `v` is guaranteed to be in the enum
                    let validator = SecondaryValidator::iter()
                        .find(|val| val.as_ref() == v)
                        .expect("validator should exist");
                    regex_rule_config = regex_rule_config.with_validator(Some(validator));
                } else if use_debug {
                    eprintln!("invalid validator: {}", v);
                }
            }
        }

        if !self.pattern_capture_groups.is_empty() {
            regex_rule_config =
                regex_rule_config.with_pattern_capture_groups(self.pattern_capture_groups.clone());
        }

        let mut rule_config =
            RootRuleConfig::new(regex_rule_config).match_action(MatchAction::None);

        if let Some(match_validation) = &self.match_validation {
            if let Ok(mvt) = match_validation.try_into() {
                rule_config = rule_config.third_party_active_checker(mvt);
            } else if use_debug {
                eprintln!("invalid validation: {:?}", match_validation);
            }
        }

        rule_config
    }
}

impl DiffAware for SecretRule {
    fn generate_diff_aware_digest(&self) -> String {
        format!("{}:{}", self.id, self.pattern).to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_try_to_secondary_validator_with_jwt_config() {
        let validator = SecretRuleValidator {
            type_: "JwtClaimsValidator".to_string(),
            config: Some(serde_json::json!({
                "required_claims": {
                    "aa_id": {"type":"Present"}
                },
                "required_headers": {
                     "itt": {"type":"ExactValue","config":"at"}
                }
            })),
        };

        let result = validator.try_to_secondary_validator(false);
        assert!(result.is_some());

        // Verify the validator is a JwtClaimsValidator with correct config
        if let SecondaryValidator::JwtClaimsValidator { config } = result.unwrap() {
            // Check that required_claims contains the aa_id key
            assert!(config.required_claims.contains_key("aa_id"));
            assert_eq!(config.required_claims.len(), 1);
            // Check that required_headers contains the itt key
            assert!(config.required_headers.contains_key("itt"));
            assert_eq!(config.required_headers.len(), 1);
        } else {
            panic!("Expected JwtClaimsValidator variant");
        }
    }

    #[test]
    fn test_try_to_secondary_validator_invalid_type() {
        let validator = SecretRuleValidator {
            type_: "InvalidValidator".to_string(),
            config: None,
        };

        let result = validator.try_to_secondary_validator(false);
        assert!(result.is_none());
    }

    #[test]
    fn test_try_to_secondary_validator_known_type_without_config() {
        // LuhnChecksum is a known validator that doesn't require config
        // Test that if a config is provided, we don't panic and return None
        let validator = SecretRuleValidator {
            type_: "LuhnChecksum".to_string(),
            config: Some(serde_json::json!({
                "test": "test"
            })),
        };

        let result = validator.try_to_secondary_validator(false);
        assert!(result.is_none());
    }

    #[test]
    fn test_convert_to_sds_ruleconfig_with_validators_v2() {
        let rule = SecretRule {
            id: "test-rule".to_string(),
            sds_id: "sds-123".to_string(),
            name: "Test Rule".to_string(),
            description: "Test description".to_string(),
            pattern: "test.*pattern".to_string(),
            default_included_keywords: vec![],
            default_excluded_keywords: vec![],
            look_ahead_character_count: Some(30),
            priority: RulePriority::Medium,
            validators: None,
            validators_v2: Some(vec![SecretRuleValidator {
                type_: "JwtClaimsValidator".to_string(),
                config: Some(serde_json::json!({
                    "required_claims": {
                        "aa_id": {"type":"Present"}
                    },
                    "required_headers": {
                        "itt": {"type":"ExactValue","config":"at"}
                    }
                })),
            }]),
            match_validation: None,
            pattern_capture_groups: vec!["sds_match".to_string()],
        };

        // Validates that convert_to_sds_ruleconfig doesn't panic and returns a valid config.
        let _config = rule.convert_to_sds_ruleconfig(false);
    }

    #[test]
    fn test_custom_http_v2_conversion() {
        // Test that CustomHttpV2 config can be properly converted to dd-sds types
        let http_v2_config = SecretRuleMatchValidationHttpV2 {
            match_pairing: Some(SecretRuleMatchPairingConfig {
                kind: "test_vendor".to_string(),
                parameters: {
                    let mut params = BTreeMap::new();
                    params.insert("client_id".to_string(), "$CLIENT_ID".to_string());
                    params
                },
            }),
            calls: vec![SecretRuleHttpCallConfig {
                request: SecretRuleHttpRequestConfig {
                    endpoint: "https://api.example.com/validate?secret=$MATCH".to_string(),
                    method: SecretRuleMatchValidationHttpMethod::Post,
                    hosts: vec!["us1".to_string(), "eu1".to_string()],
                    headers: {
                        let mut headers = BTreeMap::new();
                        headers.insert(
                            "Authorization".to_string(),
                            "Bearer %base64($CLIENT_ID:$MATCH)".to_string(),
                        );
                        headers
                    },
                    body: Some(r#"{"token": "$MATCH"}"#.to_string()),
                    timeout_seconds: Some(5),
                },
                response: SecretRuleHttpResponseConfig {
                    conditions: vec![
                        SecretRuleResponseCondition {
                            condition_type: SecretRuleResponseConditionType::Valid,
                            status_code: Some(SecretRuleStatusCodeMatcher::Single { single: 200 }),
                            raw_body: None,
                            body: None,
                        },
                        SecretRuleResponseCondition {
                            condition_type: SecretRuleResponseConditionType::Invalid,
                            status_code: Some(SecretRuleStatusCodeMatcher::Range {
                                range: SecretRuleStatusCodeRange {
                                    start: 400,
                                    end: 500,
                                },
                            }),
                            raw_body: Some(SecretRuleBodyMatcher::Regex {
                                regex: "^error.*".to_string(),
                            }),
                            body: None,
                        },
                    ],
                },
            }],
            provides: vec![
                SecretRulePairedValidatorConfig {
                    kind: "datadog".to_string(),
                    name: "api_key".to_string(),
                },
                SecretRulePairedValidatorConfig {
                    kind: "datadog".to_string(),
                    name: "app_key".to_string(),
                },
            ],
        };

        let validation = SecretRuleMatchValidation::CustomHttpV2(http_v2_config);

        // Convert to dd-sds MatchValidationType
        let result: Result<MatchValidationType, &str> = (&validation).try_into();
        assert!(result.is_ok());

        if let Ok(MatchValidationType::CustomHttpV2(config)) = result {
            // Verify match pairing
            assert!(config.match_pairing.is_some());
            let pairing = config.match_pairing.unwrap();
            assert_eq!(pairing.kind, "test_vendor");
            assert_eq!(pairing.parameters.len(), 1);

            // Verify calls
            assert_eq!(config.calls.len(), 1);
            let call = &config.calls[0];

            // Verify request
            assert_eq!(call.request.method, HttpMethod::Post);
            assert_eq!(call.request.hosts.len(), 2);
            assert_eq!(call.request.headers.len(), 1);
            assert!(call.request.body.is_some());

            // Verify response conditions
            assert_eq!(call.response.conditions.len(), 2);
            assert_eq!(
                call.response.conditions[0].condition_type,
                ResponseConditionType::Valid
            );
            assert_eq!(
                call.response.conditions[1].condition_type,
                ResponseConditionType::Invalid
            );

            // Verify provides
            assert!(config.provides.is_some());
            let provides = config.provides.unwrap();
            assert_eq!(provides.len(), 2);
            assert_eq!(provides[0].kind, "datadog");
            assert_eq!(provides[0].name, "api_key");
            assert_eq!(provides[1].kind, "datadog");
            assert_eq!(provides[1].name, "app_key");
        } else {
            panic!("Expected CustomHttpV2 variant");
        }
    }

    #[test]
    fn test_deserialize_custom_http_v2() {
        let json = r#"{
  "match_pairing":{
    "kind":"datadog",
    "parameters":{
      "api_key":"$API_KEY",
      "app_key":"$APP_KEY"
    }
  },
  "calls":[
    {
      "request":{
        "endpoint":"https://generativelanguage.googleapis.com/v1beta/models/*:countTokens?key=$API_KEY",
        "method":"POST",
        "headers":{
          "User-Agent":"Datadog Match Validator",
          "api-key":"$MATCH"
        },
        "timeout_seconds":3
      },
      "response":{
        "conditions":[
          {
            "condition_type":"Valid",
            "status_code":{
              "single":400
            },
            "body":{
              "@type":{
                "exact_match":"type.googleapis.com/google.rpc.BadRequest"
              }
            }
          },
          {
            "condition_type":"Valid",
            "status_code":{
              "single":403
            },
            "body":{
              "status":{
                "exact_match":"PERMISSION_DENIED"
              }
            }
          },
          {
            "condition_type":"Invalid",
            "status_code":{
              "single":400
            },
            "body":{
              "message":{
                "exact_match":"API key not valid. Please pass a valid API key."
              }
            }
          }
        ]
      }
    }
  ],
  "provides":[
    {
      "kind":"datadog",
      "name":"api_key"
    },
    {
      "kind":"datadog",
      "name":"app_key"
    }
  ]
}
"#;
        let secret_rule_match_validation_http_v2: SecretRuleMatchValidationHttpV2 =
            serde_json::from_str(json).unwrap();

        // Assert contents
        let mut parameters = BTreeMap::new();
        parameters.insert("api_key".to_string(), "$API_KEY".to_string());
        parameters.insert("app_key".to_string(), "$APP_KEY".to_string());

        let mut headers = BTreeMap::new();
        headers.insert(
            "User-Agent".to_string(),
            "Datadog Match Validator".to_string(),
        );
        headers.insert("api-key".to_string(), "$MATCH".to_string());

        let mut body0 = BTreeMap::new();
        body0.insert(
            "@type".to_string(),
            SecretRuleBodyMatcher::ExactMatch {
                exact_match: "type.googleapis.com/google.rpc.BadRequest".to_string(),
            },
        );
        let mut body1 = BTreeMap::new();
        body1.insert(
            "status".to_string(),
            SecretRuleBodyMatcher::ExactMatch {
                exact_match: "PERMISSION_DENIED".to_string(),
            },
        );
        let mut body2 = BTreeMap::new();
        body2.insert(
            "message".to_string(),
            SecretRuleBodyMatcher::ExactMatch {
                exact_match: "API key not valid. Please pass a valid API key.".to_string(),
            },
        );

        assert_eq!(secret_rule_match_validation_http_v2, SecretRuleMatchValidationHttpV2 {
            match_pairing: Some(SecretRuleMatchPairingConfig {
                kind: "datadog".to_string(),
                parameters,
            }),
            calls: vec![SecretRuleHttpCallConfig {
                request: SecretRuleHttpRequestConfig {
                    endpoint: "https://generativelanguage.googleapis.com/v1beta/models/*:countTokens?key=$API_KEY".to_string(),
                    method: SecretRuleMatchValidationHttpMethod::Post,
                    hosts: vec![],
                    headers,
                    body: None,
                    timeout_seconds: Some(3),
                },
                response: SecretRuleHttpResponseConfig {
                    conditions: vec![
                        SecretRuleResponseCondition {
                            condition_type: SecretRuleResponseConditionType::Valid,
                            status_code: Some(SecretRuleStatusCodeMatcher::Single { single: 400 }),
                            raw_body: None,
                            body: Some(body0),
                        },
                        SecretRuleResponseCondition {
                            condition_type: SecretRuleResponseConditionType::Valid,
                            status_code: Some(SecretRuleStatusCodeMatcher::Single { single: 403 }),
                            raw_body: None,
                            body: Some(body1),
                        },
                        SecretRuleResponseCondition {
                            condition_type: SecretRuleResponseConditionType::Invalid,
                            status_code: Some(SecretRuleStatusCodeMatcher::Single { single: 400 }),
                            raw_body: None,
                            body: Some(body2),
                        },
                    ],
                },
            }],
            provides: vec![
                SecretRulePairedValidatorConfig {
                    kind: "datadog".to_string(),
                    name: "api_key".to_string(),
                },
                SecretRulePairedValidatorConfig {
                    kind: "datadog".to_string(),
                    name: "app_key".to_string(),
                },
            ],
        });
    }
}
