// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

/// This trait defines what is required for diff-aware to run correctly. Diff-aware needs to
/// be activated for a certain configuration. All elements that makes the configuration
/// or the results change should implement this trait and generate a unique string
/// that is used to produce a configuration hash.
pub trait DiffAware {
    /// The string that generates a string used to produce a unique hash for the configuration.
    /// This string should always be the same at each run if the configuration did not change.
    fn generate_diff_aware_digest(&self) -> String;
}
