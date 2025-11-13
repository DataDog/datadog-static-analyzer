// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::model::secret_rule::SecretRuleMatchValidation::CustomHttp;
use common::model::diff_aware::DiffAware;
use dd_sds::SecondaryValidator;
use dd_sds::{
    AwsConfig, AwsType, CustomHttpConfig, HttpMethod, HttpStatusCodeRange, MatchAction,
    MatchValidationType, ProximityKeywordsConfig, RegexRuleConfig, RootRuleConfig,
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
    // TODO: Remove JwtClaimsValidator filter once it's config field is supported from the API.
    static ref ALLOWED_VALIDATORS: HashSet<String> = {
        SecondaryValidator::iter()
            .filter(|v| v.as_ref() != "JwtClaimsValidator")
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
    pub match_validation: Option<SecretRuleMatchValidation>,
    pub sds_id: String,
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

        if let Some(validators) = &self.validators {
            // TODO: When sds version is bumped, will need to support JwtClaimsValidator configurations.
            for v in validators {
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
