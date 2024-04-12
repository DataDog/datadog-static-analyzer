// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::rule_file::validator::http::{RawAction, RawActionReturn, RawControlFlow};
use crate::rule_file::{RawSecretStatus, RawSeverity};
use secrets_core::validator::http::NextAction;
use secrets_core::validator::{SecretCategory, Severity};

pub mod http;

impl From<RawAction> for NextAction {
    fn from(value: RawAction) -> Self {
        match value {
            RawAction::Return(raw) => NextAction::ReturnResult(raw.into()),
            RawAction::ControlFlow(raw) => raw.into(),
        }
    }
}

impl From<RawActionReturn> for SecretCategory {
    fn from(value: RawActionReturn) -> Self {
        let severity: Severity = value.severity.into();
        match value.status {
            RawSecretStatus::Valid => Self::Valid(severity),
            RawSecretStatus::Invalid => Self::Invalid(severity),
            RawSecretStatus::Inconclusive => Self::Inconclusive(severity),
        }
    }
}

impl From<RawSeverity> for Severity {
    fn from(value: RawSeverity) -> Self {
        match value {
            RawSeverity::Error => Self::Error,
            RawSeverity::Warning => Self::Warning,
            RawSeverity::Notice => Self::Notice,
            RawSeverity::Info => Self::Info,
        }
    }
}

impl From<RawControlFlow> for NextAction {
    fn from(value: RawControlFlow) -> Self {
        match value {
            RawControlFlow::Retry => Self::Retry,
            RawControlFlow::Break => Self::Abort,
        }
    }
}
