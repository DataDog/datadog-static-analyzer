// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

mod hs_matcher;
pub use hs_matcher::{Hyperscan, HyperscanBuilder, HyperscanBuilderError};
mod pattern;
pub use pattern::Pattern;
pub mod pattern_set;
pub(crate) use pattern_set::PatternSet;
mod scratch;
mod transform;
