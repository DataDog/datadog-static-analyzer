// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use std::collections::HashMap;
use std::ops::Range;
use std::string::ToString;
use common::model::diff_aware::DiffAware;
use dd_sds::{HttpValidatorConfigBuilder, MatchAction, MatchValidationType, ProximityKeywordsConfig, RegexRuleConfig, HttpMethod, AwsConfig, RequestHeader};
use dd_sds::AwsType::{AwsId, AwsSecret, AwsSession};
use dd_sds::SecondaryValidator::JwtExpirationChecker;
use serde::{Deserialize, Serialize};

const DEFAULT_LOOK_AHEAD_CHARACTER_COUNT: usize = 30;
const AWS_ID_STRING: &str = "AwsId";

const AWS_SECRET_STRING: &str = "AwsSecret";
const AWS_SESSION_STRING: &str = "AwsSession";
const CUSTOM_HTTP_STRING: &str = "CustomHttp";

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SecretRuleMatchValidationHttpCode {
    pub start: u16,
    pub end: u16,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum SecretRuleMatchValidationHttpMethod {
    #[serde(rename = "GET")]
    Get,
    #[serde(rename = "POST")]
    Post,
    #[serde(rename = "PUT")]
    Put,
    #[serde(rename = "PATCH")]
    Patch,
    #[serde(rename = "DELETE")]
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


#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SecretRuleMatchValidation {
    #[serde(rename = "type")]
    pub r#type: String,
    pub endpoint: Option<String>,
    pub hosts: Option<Vec<String>>,
    pub request_headers: Option<HashMap<String, String>>,
    pub http_method: Option<SecretRuleMatchValidationHttpMethod>,
    pub timeout_seconds: Option<u64>,
    pub valid_http_status_code: Option<Vec<SecretRuleMatchValidationHttpCode>>,
    pub invalid_http_status_code: Option<Vec<SecretRuleMatchValidationHttpCode>>,
}

impl SecretRuleMatchValidation {
    pub fn get_request_headers(&self) -> Vec<RequestHeader> {
        if let Some(rhs) = &self.request_headers {
            rhs.iter().map(|(k, v)| {
                RequestHeader{
                    key: k.clone(),
                    value: v.clone()
                }
            }).collect()
        } else {
            Vec::new()
        }
    }
}

impl TryFrom<SecretRuleMatchValidation>  for MatchValidationType {


    type Error = &'static str;

    fn try_from(value: SecretRuleMatchValidation) -> Result<Self, Self::Error> {
        match value.r#type.as_str() {
            AWS_ID_STRING => {
                Ok(MatchValidationType::Aws(AwsId))
            }
            AWS_SECRET_STRING => {
                Ok(MatchValidationType::Aws(AwsSecret(AwsConfig::default())))
            }
            AWS_SESSION_STRING => {
                Ok(MatchValidationType::Aws(AwsSession))
            }
            CUSTOM_HTTP_STRING => {
                let invalid_ports: Vec<Range<u16>> = value.invalid_http_status_code.clone().unwrap_or(vec![]).iter().map(|v| {
                    Range{start: v.start.into(), end: v.end.into()}
                }).collect();
                let valid_ports: Vec<Range<u16>> = value.valid_http_status_code.clone().unwrap_or(vec![]).iter().map(|v| {
                    Range{start: v.start.into(), end: v.end.into()}
                }).collect();
                Ok(MatchValidationType::CustomHttp(
                    HttpValidatorConfigBuilder::new(value.endpoint.clone().unwrap())
                        .set_hosts(value.hosts.clone().unwrap_or(vec![]))
                        .set_invalid_http_status_code(invalid_ports)
                        .set_request_header(
                            value.clone().get_request_headers()
                        )
                        .set_valid_http_status_code(valid_ports)
                        .set_method(value.http_method.unwrap().into())
                        .build()
                        .unwrap()
                ))
            }

            _ => {Err("invalid type")}
        }
    }
}

// This is the secret rule exposed by SDS
#[derive(Clone, Deserialize, Debug, Serialize)]
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
            if validators.contains(&"JwtExpirationChecker".to_string()) {
                rule_config = rule_config.validator(JwtExpirationChecker);
            }
        }

        if let Some(match_validation) = &self.match_validation {
            if let Ok(mvt) = match_validation.clone().try_into() {
                rule_config = rule_config.match_validation_type(mvt);
            } else {
                if use_debug {
                    eprintln!("invalid validation: {:?}", match_validation);
                }
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
