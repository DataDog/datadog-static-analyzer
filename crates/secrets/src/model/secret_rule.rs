// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::model::secret_rule::SecretRuleMatchValidation::CustomHttp;
use common::model::diff_aware::DiffAware;
use dd_sds::SecondaryValidator::JwtExpirationChecker;
use dd_sds::{
    AwsConfig, AwsType, HttpMethod, HttpValidatorConfigBuilder, MatchAction, MatchValidationType,
    ProximityKeywordsConfig, RegexRuleConfig, RequestHeader,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ops::Range;
use std::string::ToString;
use std::time::Duration;

const DEFAULT_LOOK_AHEAD_CHARACTER_COUNT: usize = 30;

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct SecretRuleMatchValidationHttpCode {
    pub start: u16,
    pub end: u16,
}

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum SecretRuleMatchValidationHttpMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
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

impl TryFrom<SecretRuleMatchValidation> for MatchValidationType {
    type Error = &'static str;

    fn try_from(value: SecretRuleMatchValidation) -> Result<Self, Self::Error> {
        match value {
            SecretRuleMatchValidation::AwsId => Ok(MatchValidationType::Aws(AwsType::AwsId)),
            SecretRuleMatchValidation::AwsSecret => Ok(MatchValidationType::Aws(
                AwsType::AwsSecret(AwsConfig::default()),
            )),
            SecretRuleMatchValidation::AwsSession => {
                Ok(MatchValidationType::Aws(AwsType::AwsSession))
            }
            CustomHttp(custom_http) => {
                let invalid_ports: Vec<Range<u16>> = custom_http
                    .invalid_http_status_code
                    .clone()
                    .iter()
                    .map(|v| Range {
                        start: v.start,
                        end: v.end,
                    })
                    .collect();
                let valid_ports: Vec<Range<u16>> = custom_http
                    .valid_http_status_code
                    .clone()
                    .iter()
                    .map(|v| Range {
                        start: v.start,
                        end: v.end,
                    })
                    .collect();
                Ok(MatchValidationType::CustomHttp(
                    HttpValidatorConfigBuilder::new(custom_http.endpoint.clone())
                        .set_hosts(custom_http.hosts.clone())
                        .set_invalid_http_status_code(invalid_ports)
                        .set_timeout(Duration::from_secs(custom_http.timeout_seconds.unwrap()))
                        .set_request_header(custom_http.clone().get_request_headers())
                        .set_valid_http_status_code(valid_ports)
                        .set_method(custom_http.http_method.into())
                        .build()
                        .unwrap(),
                ))
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct SecretRuleMatchValidationHttp {
    pub endpoint: String,
    pub hosts: Vec<String>,
    pub request_headers: HashMap<String, String>,
    pub http_method: SecretRuleMatchValidationHttpMethod,
    pub timeout_seconds: Option<u64>,
    pub valid_http_status_code: Vec<SecretRuleMatchValidationHttpCode>,
    pub invalid_http_status_code: Vec<SecretRuleMatchValidationHttpCode>,
}

impl SecretRuleMatchValidationHttp {
    pub fn get_request_headers(&self) -> Vec<RequestHeader> {
        self.request_headers
            .iter()
            .map(|(k, v)| RequestHeader {
                key: k.clone(),
                value: v.clone(),
            })
            .collect()
    }
}

// This is the secret rule exposed by SDS
#[derive(Clone, Deserialize, Debug, Serialize, Eq, PartialEq)]
pub struct SecretRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub pattern: String,
    pub default_included_keywords: Vec<String>,
    pub validators: Option<Vec<String>>,
    pub match_validation: Option<SecretRuleMatchValidation>,
}

impl SecretRule {
    const VALIDATOR_JWT_EXPIRATION_CHECKER: &'static str = "JwtExpirationChecker";

    /// Convert the rule into a configuration usable by SDS.
    pub fn convert_to_sds_ruleconfig(&self, use_debug: bool) -> RegexRuleConfig {
        let mut rule_config = RegexRuleConfig::new(&self.pattern).match_action(MatchAction::None);

        if !self.default_included_keywords.is_empty() {
            rule_config = rule_config.proximity_keywords(ProximityKeywordsConfig {
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
                rule_config = rule_config.validator(JwtExpirationChecker);
            }
        }

        if let Some(match_validation) = &self.match_validation {
            if let Ok(mvt) = match_validation.clone().try_into() {
                rule_config = rule_config.match_validation_type(mvt);
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
