// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::rule::RuleMatch;
use std::fmt::Debug;
use std::path::PathBuf;
use std::sync::Arc;

#[cfg(feature = "validator-http")]
pub mod http;

pub trait Validator {
    fn id(&self) -> &ValidatorId;

    fn validate(&self, rule_match: Candidate) -> Result<SecretCategory, ValidatorError>;
}

#[derive(Debug, thiserror::Error)]
pub enum ValidatorError {
    #[error("validator error: {err}")]
    ChildError {
        validator_type: String,
        err: Box<dyn std::error::Error + Send + Sync>,
    },
}

/// A unique id that identifies a [`Validator`].
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
#[repr(transparent)]
pub struct ValidatorId(pub Arc<str>);

impl From<&str> for ValidatorId {
    fn from(value: &str) -> Self {
        Self(Arc::from(value))
    }
}

impl From<String> for ValidatorId {
    fn from(value: String) -> Self {
        Self(Arc::from(value.as_str()))
    }
}

impl AsRef<str> for ValidatorId {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

#[derive(Debug, Clone)]
pub struct Candidate {
    pub source: PathBuf,
    pub rule_match: RuleMatch,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum SecretCategory {
    Valid(Severity),
    Invalid,
    Inconclusive,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum Severity {
    Error,
    Warning,
    Notice,
    Info,
}
