// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::rule_file::check::RawCheck;
use crate::rule_file::raw_item;

raw_item! {
    /// A secret matcher and its configuration.
    pub enum RawMatcher {
        Hyperscan(RawHyperscan),
    }

    /// The configuration for matcher `hyperscan`
    pub struct RawHyperscan {
        pub id: Option<String>,
        pub pattern: String,
        pub checks: Option<Vec<RawCheck>>,
    }
}
