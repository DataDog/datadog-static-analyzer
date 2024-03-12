// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

// NOTE: Because this crate still has some scaffolding, these ignores are added
// to (temporarily) silence clippy while iterating on the `pub` interface to expose.
#![allow(unused_imports)]
#![allow(dead_code)]

pub mod capture;
pub mod common;
pub mod engine;
pub mod location;
pub mod matcher;
pub mod rule;
pub mod rule_evaluator;
pub mod validator;
pub use validator::Validator;

// TODO: Remove re-export once a `Hyperscan` builder is implemented
pub use vectorscan;

mod worker;
