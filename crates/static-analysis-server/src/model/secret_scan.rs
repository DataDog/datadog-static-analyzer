// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use serde::{Deserialize, Serialize};

/// Request to scan code for secrets
///
/// This request type supports generic rule formats to allow flexibility
/// in how secret detection rules are provided.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretScanRequest<T = serde_json::Value> {
    /// Filename being scanned (for reporting purposes)
    pub filename: String,

    /// Source code to scan
    pub code: String,

    /// Secret detection rules to apply
    pub rules: Vec<T>,

    /// Enable debug mode
    #[serde(default)]
    pub use_debug: bool,
}

/// Response from secret scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretScanResponse {
    /// Detected secrets with positions (JSON representation of SecretResult)
    pub results: Vec<serde_json::Value>,

    /// Errors that occurred during scanning
    #[serde(default)]
    pub errors: Vec<String>,

    /// Total execution time in milliseconds
    pub execution_time_ms: u64,
}

impl SecretScanResponse {
    /// Helper to create an error response
    pub fn error(message: String) -> Self {
        Self {
            results: vec![],
            errors: vec![message],
            execution_time_ms: 0,
        }
    }
}
