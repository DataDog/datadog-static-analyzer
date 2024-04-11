// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use kernel::model::common::Position;
use kernel::model::rule::{RuleCategory, RuleSeverity};
use kernel::model::violation::Violation;
use serde::Serialize;
use std::fmt::{Display, Formatter};

/// A span of text that was detected as a potential secret, along with the validation result, if any.
#[derive(Debug, Clone)]
pub struct SecretResult {
    pub rule_id: String,
    pub file_path: String,
    pub status: ValidationStatus,
    pub violation: Violation,
}

impl SecretResult {
    pub fn new(
        rule_id: impl Into<String>,
        file_path: impl Into<String>,
        status: ValidationStatus,
        start: Position,
        end: Position,
    ) -> Self {
        let (message, severity) = match status {
            ValidationStatus::Unvalidated => (
                "A potential secret where validation was not attempted",
                RuleSeverity::None,
            ),
            ValidationStatus::Valid(sev) => ("A validated and confirmed active secret", sev),
            ValidationStatus::Invalid(sev) => ("A validated candidate that was not active", sev),
            ValidationStatus::Inconclusive(sev) => (
                "A candidate where the validation result was inconclusive",
                sev,
            ),
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

/// Metadata about a secret detection rule.
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

#[cfg(feature = "secrets")]
impl From<secrets::scanner::RuleInfo> for SecretRule {
    fn from(value: secrets::scanner::RuleInfo) -> Self {
        Self {
            rule_id: value.rule_id,
            description: value.description,
            short_description: value.short_description,
        }
    }
}

/// The validation status of a secret.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ValidationStatus {
    Valid(RuleSeverity),
    Invalid(RuleSeverity),
    Inconclusive(RuleSeverity),
    Unvalidated,
}

impl Display for ValidationStatus {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                ValidationStatus::Valid(_) => "Valid",
                ValidationStatus::Invalid(_) => "Invalid",
                ValidationStatus::Inconclusive(_) => "Inconclusive",
                ValidationStatus::Unvalidated => "Unvalidated",
            }
        )
    }
}

#[cfg(feature = "secrets")]
impl From<secrets::core::validator::SecretCategory> for ValidationStatus {
    fn from(value: secrets::core::validator::SecretCategory) -> Self {
        use secrets::core::validator::SecretCategory;
        match value {
            SecretCategory::Valid(sev) => Self::Valid(as_rule_severity(sev)),
            SecretCategory::Invalid(sev) => Self::Invalid(as_rule_severity(sev)),
            SecretCategory::Inconclusive(sev) => Self::Inconclusive(as_rule_severity(sev)),
        }
    }
}

// The following `as_*` functions work as pseudo "From" impls.
// We use this strategy to avoid adding the `secrets`crate as a dependency of the static-analysis-kernel crate.

#[cfg(feature = "secrets")]
fn as_rule_severity(severity: secrets::core::validator::Severity) -> RuleSeverity {
    use secrets::core::validator::Severity;
    match severity {
        Severity::Error => RuleSeverity::Error,
        Severity::Warning => RuleSeverity::Warning,
        Severity::Notice => RuleSeverity::Notice,
        Severity::Info => RuleSeverity::None,
    }
}

#[cfg(feature = "secrets")]
pub fn as_position(point: secrets::core::location::Point) -> Position {
    Position {
        line: point.line.get(),
        col: point.col.get(),
    }
}
