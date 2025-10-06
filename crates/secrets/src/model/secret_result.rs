// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use common::model::position::Position;
use dd_sds::MatchStatus;
use serde::{Deserialize, Serialize};
use crate::model::secret_rule::RulePriority;

#[derive(Clone, Copy, Debug, PartialEq, Hash, Eq, Serialize, Deserialize)]
pub enum SecretValidationStatus {
    NotValidated,
    Valid,
    Invalid,
    ValidationError,
    NotAvailable,
}

impl From<&MatchStatus> for SecretValidationStatus {
    fn from(value: &MatchStatus) -> Self {
        match value {
            MatchStatus::NotChecked => SecretValidationStatus::NotValidated,
            MatchStatus::Valid => SecretValidationStatus::Valid,
            MatchStatus::Invalid => SecretValidationStatus::Invalid,
            MatchStatus::Error(_) => SecretValidationStatus::ValidationError,
            MatchStatus::NotAvailable => SecretValidationStatus::NotAvailable,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Hash, Eq)]
pub struct SecretResultMatch {
    pub start: Position,
    pub end: Position,
    pub validation_status: SecretValidationStatus,
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
