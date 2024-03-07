// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

// NOTE: Because this crate still has some scaffolding, these ignores are added
// to (temporarily) silence clippy while iterating on the `pub` interface to expose.
#![allow(unused_imports)]
#![allow(dead_code)]

mod capture;
mod common;
mod location;
mod matcher;
mod rule;
mod validator;
pub use validator::Validator;
