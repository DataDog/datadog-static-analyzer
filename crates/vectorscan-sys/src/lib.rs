// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

pub mod hs {
    include!("bindings_hs.rs");
}

#[cfg(feature = "chimera")]
pub mod ch {
    include!("bindings_ch.rs");
}
