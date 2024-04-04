// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::rule_file::check::RawCheck;
use crate::rule_file::{deserialize_enum_exactly_one_of, raw_struct};

/// A secret matcher and its configuration.
#[derive(Debug, Clone)]
pub enum RawMatcher {
    Hyperscan(RawHyperscan),
}
deserialize_enum_exactly_one_of!(
    RawMatcher,
    "matcher",
    {
        "hyperscan" => RawMatcher::Hyperscan,
    }
);

raw_struct! {
    /// The configuration for matcher `hyperscan`
    pub struct RawHyperscan {
        pub id: Option<String>,
        pub pattern: String,
        pub checks: Option<Vec<RawCheck>>,
    }
}
