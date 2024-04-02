// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use kernel::model::common::Position;
use kernel::model::rule::{RuleCategory, RuleSeverity};
use kernel::model::violation::Violation;
use serde::Serialize;
use std::fmt::{Display, Formatter};

// This file contains structs that will allow us to test the secrets scanner while also
// allowing operation when the `secrets` feature is disabled.

/// This struct is used to test the secrets scanner by allowing the main binary
/// to serialize secrets scan information if it exists, but skip it if it doesn't.
#[derive(Debug, Clone)]
pub struct DetectedSecret {
    // Note: Rule information is only denormalized for the integration test.
    pub rule_id: String,
    pub file_path: String,
    pub status: ValidationStatus,
    pub violation: Violation,
}

impl DetectedSecret {
    pub fn new(
        rule_id: impl Into<String>,
        file_path: impl Into<String>,
        status: ValidationStatus,
        start: Position,
        end: Position,
    ) -> Self {
        let message = match status {
            ValidationStatus::Unvalidated => {
                "A potential secret where validation was not attempted"
            }
            ValidationStatus::Valid(_) => "A validated and confirmed active secret",
            ValidationStatus::Invalid => "A validated candidate that was not active",
            ValidationStatus::Inconclusive => {
                "A candidate where the validation result was inconclusive"
            }
        };
        let severity = match status {
            ValidationStatus::Valid(severity) => severity,
            _ => RuleSeverity::Notice,
        };

        let violation = Violation {
            start,
            end,
            message: message.to_string(),
            severity,
            category: RuleCategory::Security,
            fixes: vec![],
        };

        Self {
            rule_id: rule_id.into(),
            file_path: file_path.into(),
            status,
            violation,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SecretRule {
    pub rule_id: String,
    pub description: String,
    pub short_description: String,
}

impl SecretRule {
    pub fn new(
        rule_id: impl Into<String>,
        description: impl Into<String>,
        short_description: impl Into<String>,
    ) -> Self {
        Self {
            rule_id: rule_id.into(),
            description: description.into(),
            short_description: short_description.into(),
        }
    }
}

/// The validation status of a secret.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ValidationStatus {
    Valid(RuleSeverity),
    Invalid,
    Inconclusive,
    Unvalidated,
}

impl Display for ValidationStatus {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                ValidationStatus::Valid(_) => "Valid",
                ValidationStatus::Invalid => "Invalid",
                ValidationStatus::Inconclusive => "Inconclusive",
                ValidationStatus::Unvalidated => "Unvalidated",
            }
        )
    }
}
