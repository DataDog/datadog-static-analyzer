// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::model::secret_rule::RulePriority;
use common::model::position::Position;
use dd_sds::MatchStatus;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Hash, Eq, Serialize, Deserialize)]
pub enum SecretValidationStatus {
    NotValidated,
    Valid,
    Invalid,
    ValidationError(Vec<ValidationErrorInfo>),
    NotAvailable,
}

impl SecretValidationStatus {
    pub fn from(status: &MatchStatus, match_value: Option<&str>) -> Self {
        match status {
            MatchStatus::NotChecked => SecretValidationStatus::NotValidated,
            MatchStatus::Valid => SecretValidationStatus::Valid,
            MatchStatus::Invalid => SecretValidationStatus::Invalid,
            MatchStatus::ValidationError(validation_errors) => {
                let error_infos: Vec<ValidationErrorInfo> = validation_errors
                    .iter()
                    .map(|error| match error {
                        dd_sds::ValidationError::HttpError(http_error) => ValidationErrorInfo {
                            error_type: ValidationErrorType::HttpError,
                            status_code: http_error.status_code,
                            message: redact_secret(&http_error.message, match_value),
                        },
                        dd_sds::ValidationError::UnknownResponseType(unknown_response) => {
                            ValidationErrorInfo {
                                error_type: ValidationErrorType::UnknownResponseType,
                                status_code: unknown_response.status_code,
                                message: format!(
                                    "Unknown response type (body_length: {}, body_prefix: '{}')",
                                    unknown_response.body_length,
                                    redact_secret(
                                        unknown_response.body_prefix.as_deref().unwrap_or(""),
                                        match_value
                                    ),
                                ),
                            }
                        }
                    })
                    .collect();

                SecretValidationStatus::ValidationError(error_infos)
            }
            MatchStatus::NotAvailable => SecretValidationStatus::NotAvailable,
            // TODO: do we want to create a dedicated status for this?
            MatchStatus::MissingDependentMatch => SecretValidationStatus::NotValidated,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Hash, Eq)]
pub struct SecretResultMatch {
    pub start: Position,
    pub end: Position,
    pub validation_status: SecretValidationStatus,
    #[serde(default)]
    pub is_suppressed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Hash, Eq)]
pub struct SecretResult {
    pub rule_id: String,
    pub rule_name: String,
    pub filename: String,
    pub message: String,
    pub priority: RulePriority,
    pub matches: Vec<SecretResultMatch>,
}

#[derive(Debug, PartialEq, PartialOrd, Ord, Eq, Clone, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidationErrorInfo {
    #[serde(rename = "type")]
    pub error_type: ValidationErrorType,
    pub status_code: u16,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, PartialOrd, Ord, Hash, Eq, Serialize, Deserialize)]
pub enum ValidationErrorType {
    HttpError,
    UnknownResponseType,
}

impl ValidationErrorType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ValidationErrorType::HttpError => "HttpError",
            ValidationErrorType::UnknownResponseType => "UnknownResponseType",
        }
    }
}

fn redact_secret(message: &str, secret: Option<&str>) -> String {
    match secret {
        Some(secret) if !secret.is_empty() => message.replace(secret, "[REDACTED]"),
        _ => message.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    #[test]
    fn test_redact_secret_replaces_match_value() {
        let msg = "Error making HTTP request: connection refused for MY_SECRET123";
        let redacted = redact_secret(msg, Some("MY_SECRET123"));
        assert_eq!(
            redacted,
            "Error making HTTP request: connection refused for [REDACTED]"
        );
    }

    #[test]
    fn test_redact_secret_no_match_value() {
        let msg = "Error making HTTP request: connection refused";
        assert_eq!(redact_secret(msg, None), msg);
    }

    #[test]
    fn test_serialize_validation_error_info() {
        let error_info = ValidationErrorInfo {
            error_type: ValidationErrorType::HttpError,
            status_code: 400,
            message: "Invalid token".to_string(),
        };

        let expected = serde_json::json!({
            "type": "HttpError",
            "statusCode": 400,
            "message": "Invalid token"
        });

        let actual = serde_json::to_value(&error_info).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_deserialize_validation_error_info() {
        let json = serde_json::json!({
            "type": "HttpError",
            "statusCode": 401,
            "message": "Unauthorized access"
        });

        let expected = ValidationErrorInfo {
            error_type: ValidationErrorType::HttpError,
            status_code: 401,
            message: "Unauthorized access".to_string(),
        };

        let actual: ValidationErrorInfo = serde_json::from_value(json).unwrap();
        assert_eq!(actual, expected);
    }
}
