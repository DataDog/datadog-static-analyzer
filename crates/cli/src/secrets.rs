// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use kernel::model::common::Position;
use kernel::model::rule::{RuleCategory, RuleSeverity};
use kernel::model::violation::Violation;
use serde::Serialize;
use sha2::{Digest, Sha256};
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
    /// The SHA256 hash of the secret
    pub text_hash: [u8; 32],
}

impl DetectedSecret {
    pub fn new(
        rule_id: impl Into<String>,
        file_path: impl Into<String>,
        status: ValidationStatus,
        start: Position,
        end: Position,
        content: &str,
    ) -> Self {
        let text_hash: [u8; 32] = Sha256::digest(content.as_bytes()).into();

        let violation = Violation {
            start,
            end,
            // TODO: This will eventually be dynamic
            message: "Unvalidated potential secret".to_string(),
            // TODO: This will eventually be dynamic
            severity: RuleSeverity::Notice,
            category: RuleCategory::Security,
            fixes: vec![],
        };

        Self {
            rule_id: rule_id.into(),
            file_path: file_path.into(),
            status,
            violation,
            text_hash,
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
