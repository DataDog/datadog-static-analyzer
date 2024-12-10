// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

mod tests;
pub use tests::is_test_file;

/// Metadata associated with an artifact that has been analyzed.
#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct ArtifactClassification {
    /// Whether the artifact is considered a "test file" or not. A test file is
    /// language-dependent and either contains unit tests or is associated with unit test frameworks.
    pub is_test_file: bool,
}
