// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

mod common;
pub mod compiler;
pub use compiler::{Pattern, PatternBuilder};
pub mod database;
pub mod error;
pub use error::Error;
pub mod runtime;
pub use runtime::Scratch;
pub mod scan;
pub use scan::HsMatch;
