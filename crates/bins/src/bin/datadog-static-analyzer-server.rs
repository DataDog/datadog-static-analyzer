// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use kernel::analysis::ddsa_lib::v8_platform::{initialize_v8, Initialized, V8Platform};
use std::sync::OnceLock;
mod datadog_static_analyzer_server;

pub(crate) static V8_PLATFORM: OnceLock<V8Platform<Initialized>> = OnceLock::new();
pub(crate) static RAYON_POOL: OnceLock<rayon::ThreadPool> = OnceLock::new();

#[rocket::main]
async fn main() {
    // NOTE: It's imperative that the Rayon pool (which will handle analysis jobs that use v8)
    // is created by the same thread that initializes v8 (see the documentation
    // on the `initialize_v8` function for more information).
    let v8 = initialize_v8(0);
    V8_PLATFORM.set(v8).expect("cell should have been unset");

    let rayon_pool = rayon::ThreadPoolBuilder::new()
        .num_threads(0)
        .build()
        .expect("rayon pool should be buildable");
    RAYON_POOL
        .set(rayon_pool)
        .expect("cell should have been unset");

    datadog_static_analyzer_server::start().await;
}
