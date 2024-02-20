// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use bitflags::bitflags;
use vectorscan_sys::hs;

bitflags! {
    /// Flags that are used for the mode parameter of the various compile calls ([`hs::hs_compile`],
    /// [`hs::hs_compile_multi`], and [`hs::hs_compile_ext_multi`])
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct Mode: u32 {
        /// Block scan (non-streaming) database
        const BLOCK = hs::HS_MODE_BLOCK;
        /// Alias for [Self::BLOCK]
        const NOSTREAM = hs::HS_MODE_NOSTREAM;
        /// Streaming database
        const STREAM = hs::HS_MODE_STREAM;
        /// Vectored scanning database
        const VECTORED = hs::HS_MODE_VECTORED;
        /// Use full precision to track start of match offsets in stream state.
        ///
        /// This mode will use the most stream state per pattern, but will always return
        /// an accurate start of match offset regardless of how far back in the past it
        /// was found.
        const SOM_HORIZON_LARGE = hs::HS_MODE_SOM_HORIZON_LARGE;
        /// Use medium precision to track start of match offsets in stream state.
        ///
        /// This mode will use less stream state than [Self::SOM_HORIZON_LARGE] and
        /// will limit start of match accuracy to offsets within 2^32 bytes of the
        /// end of match offset reported.
        const SOM_HORIZON_MEDIUM = hs::HS_MODE_SOM_HORIZON_MEDIUM;
        /// Use limited precision to track start of match offsets in stream state.
        ///
        /// This mode will use less stream state than [Self::SOM_HORIZON_LARGE] and
        /// will limit start of match accuracy to offsets within 2^16 bytes of the
        /// end of match offset reported.
        const SOM_HORIZON_SMALL = hs::HS_MODE_SOM_HORIZON_SMALL;
    }
}
