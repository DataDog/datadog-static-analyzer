// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::model::secret_rule::SecretRuleMatchValidation::CustomHttp;
use common::model::diff_aware::DiffAware;
use dd_sds::SecondaryValidator::JwtExpirationChecker;
use dd_sds::{
    AwsConfig, AwsType, CustomHttpConfig, HttpMethod, HttpStatusCodeRange, MatchAction,
    MatchValidationType, ProximityKeywordsConfig, RegexRuleConfig, RootRuleConfig,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

const DEFAULT_LOOK_AHEAD_CHARACTER_COUNT: usize = 30;

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

#[derive(Copy, Clone, Deserialize, Debug, Serialize, Eq, PartialEq)]
pub enum RulePriority {
    #[serde(rename = "info")]
    Info,
    #[serde(rename = "low")]
    Low,
    #[serde(rename = "medium")]
    Medium,
    #[serde(rename = "high")]
    High,
    #[serde(rename = "critical")]
    Critical,
    #[serde(rename = "high")]
    None,
}

impl TryFrom<&str> for RulePriority {
    type Error = &'static str;

    fn try_from(s: &str) -> Result<Self, &'static str> {
        match s.to_lowercase().as_str() {
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
        match self {
            Self::Info => write!(f, "error"),
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
            Self::None => write!(f, "none"),
        }
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
    pub validators: Option<Vec<String>>,
    pub match_validation: Option<SecretRuleMatchValidation>,
    pub sds_id: String,
}

impl SecretRule {
    const VALIDATOR_JWT_EXPIRATION_CHECKER: &'static str = "JwtExpirationChecker";

    /// Convert the rule into a configuration usable by SDS.
    pub fn convert_to_sds_ruleconfig(&self, use_debug: bool) -> RootRuleConfig<RegexRuleConfig> {
        let mut regex_rule_config = RegexRuleConfig::new(&self.pattern);

        if !self.default_included_keywords.is_empty() {
            regex_rule_config =
                regex_rule_config.with_proximity_keywords(ProximityKeywordsConfig {
                    look_ahead_character_count: DEFAULT_LOOK_AHEAD_CHARACTER_COUNT,
                    included_keywords: self.default_included_keywords.clone(),
                    excluded_keywords: vec![],
                });
        }

        if let Some(validators) = &self.validators {
            if validators
                .iter()
                .any(|v| v == SecretRule::VALIDATOR_JWT_EXPIRATION_CHECKER)
            {
                regex_rule_config = regex_rule_config.with_validator(Some(JwtExpirationChecker));
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
