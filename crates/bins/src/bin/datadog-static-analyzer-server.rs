// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use kernel::analysis::ddsa_lib::v8_platform::{initialize_v8, Initialized, V8Platform};
use std::sync::OnceLock;
mod datadog_static_analyzer_server;

pub(crate) static V8_PLATFORM: OnceLock<V8Platform<Initialized>> = OnceLock::new();

#[rocket::main]
async fn main() {
    let v8 = initialize_v8(0).expect("v8 should have been previously uninit");
    V8_PLATFORM
        .set(v8)
        .expect("OnceLock should have been uninitialized");
    datadog_static_analyzer_server::start().await;
}
