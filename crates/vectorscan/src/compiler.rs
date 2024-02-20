// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

pub mod error;
pub use error::CompileError;
mod mode;
pub use mode::Mode;
pub mod pattern;
pub use pattern::Pattern;
