// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::rule_file::{raw_item, StringOrInt, StringsOrInts, TemplateVar};

raw_item! {
    /// A check and its configuration.
    pub enum RawCheck {
        Equals(RawEquals),
        AnyOf(RawAnyOf),
        Contains(RawContains),
        NormalizedEntropy(RawNormalizedEntropy),
    }

    /// The configuration for check `equals`
    pub struct RawEquals {
        /// The variable to check for equality
        pub input: TemplateVar,
        /// The string or integer value to check against
        pub value: StringOrInt,
    }

    /// The configuration for check `any_of`
    pub struct RawAnyOf {
        /// The variable to check for equality
        pub input: TemplateVar,
        /// A list of either string or integer values to check against
        pub values: StringsOrInts,
    }

    /// The configuration for check `contains`
    pub struct RawContains {
        /// The string variable to check
        pub input: TemplateVar,
        /// The substring to search for
        pub substring: String,
    }

    /// The configuration for check `normalized-entropy`
    pub struct RawNormalizedEntropy {
        /// The variable to measure the entropy of.
        pub input: TemplateVar,
        /// The threshold at which this check will return true.
        pub over_threshold: f32,
        /// The number of possible characters, used to normalize the entropy calculation.
        pub base: Option<u8>,
    }
}

impl RawCheck {
    /// Returns the name of the input variable for this check.
    pub fn input_variable(&self) -> &str {
        match self {
            RawCheck::Equals(raw) => raw.input.name(),
            RawCheck::AnyOf(raw) => raw.input.name(),
            RawCheck::Contains(raw) => raw.input.name(),
            RawCheck::NormalizedEntropy(raw) => raw.input.name(),
        }
    }
}
