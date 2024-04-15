// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::check::entropy::NormalizedEntropy;
use crate::check::simple::{AnyOf, Contains, Equals};
use crate::rule_file::check::RawCheck;
use crate::rule_file::StringsOrInts;
use secrets_core::Checker;

pub(crate) mod entropy;
pub(crate) mod simple;

#[derive(Debug, Clone)]
pub(crate) enum Check {
    Equals(Equals),
    AnyOf(AnyOf),
    Contains(Contains),
    Entropy(NormalizedEntropy),
}

impl Checker for Check {
    fn check(&self, input: &[u8]) -> bool {
        match &self {
            Check::Equals(ch) => ch.check(input),
            Check::AnyOf(ch) => ch.check(input),
            Check::Contains(ch) => ch.check(input),
            Check::Entropy(ch) => ch.check(input),
        }
    }
}

impl Check {
    pub(crate) fn from_raw(raw: &RawCheck) -> Self {
        match raw {
            RawCheck::Equals(raw) => Equals::new(raw.value.clone()).into(),
            RawCheck::AnyOf(raw) => {
                let kind = match raw.values.clone() {
                    StringsOrInts::Strings(strs) => AnyOf::new(strs),
                    StringsOrInts::Integers(ints) => AnyOf::new(ints),
                };
                kind.into()
            }
            RawCheck::Contains(raw) => Contains::new(&raw.substring).into(),
            RawCheck::NormalizedEntropy(raw) => {
                NormalizedEntropy::new(raw.over_threshold, raw.base).into()
            }
        }
    }
}
