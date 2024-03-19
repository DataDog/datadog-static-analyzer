// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

pub mod hs {
    #[cfg(not(target_family = "windows"))]
    include!("vectorscan_bindings_hs.rs");
    #[cfg(target_family = "windows")]
    include!("hyperscan_bindings_hs.rs");
}

#[cfg(feature = "chimera")]
pub mod ch {
    #[cfg(not(target_family = "windows"))]
    include!("vectorscan_bindings_ch.rs");
    #[cfg(target_family = "windows")]
    include!("hyperscan_bindings_ch.rs");
}
