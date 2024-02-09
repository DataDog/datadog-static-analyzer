// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use std::fmt::{Display, Formatter};
use vectorscan_sys::hs;

/// A type for runtime Hyperscan function errors
#[repr(transparent)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct ErrorCode(pub i32);

impl ErrorCode {
    /// The engine completed normally.
    pub const SUCCESS: Self = Self(hs::HS_SUCCESS);
    /// A parameter passed to this function was invalid.
    ///
    /// This error is only returned in cases where the function can detect an invalid parameter.
    /// It cannot be relied upon to detect (for example) pointers to freed memory or other invalid data.
    pub const INVALID: Self = Self(hs::HS_INVALID);
    /// A memory allocation failed.
    pub const NO_MEM: Self = Self(hs::HS_NOMEM);
    /// The engine was terminated by callback.
    ///
    /// This return value indicates that the target buffer was partially scanned, but that the
    /// callback function requested that scanning cease after a match was located.
    pub const SCAN_TERMINATED: Self = Self(hs::HS_SCAN_TERMINATED);
    /// The pattern compiler failed, and the [`CompileError`](crate::compiler::CompileError) should be inspected for more detail
    pub const COMPILER_ERROR: Self = Self(hs::HS_COMPILER_ERROR);
    /// The given database was built for a different version of Hyperscan.
    pub const DB_VERSION_ERROR: Self = Self(hs::HS_DB_VERSION_ERROR);
    /// The given database was built for a different platform (i.e., CPU type).
    pub const DB_PLATFORM_ERROR: Self = Self(hs::HS_DB_PLATFORM_ERROR);
    /// The given database was built for a different mode of operation. This error is returned when
    /// streaming calls are used with a block or vectored database and vice versa.
    pub const DB_MODE_ERROR: Self = Self(hs::HS_DB_MODE_ERROR);
    /// A parameter passed to this function was not correctly aligned.
    pub const BAD_ALIGN: Self = Self(hs::HS_BAD_ALIGN);
    /// The memory allocator (either malloc() or the allocator set with hs_set_allocator()) did not
    /// correctly return memory suitably aligned for the largest representable data type on this platform.
    pub const BAD_ALLOC: Self = Self(hs::HS_BAD_ALLOC);
    /// The scratch region was already in use.
    ///
    /// This error is returned when Hyperscan is able to detect that the scratch region given is
    /// already in use by another Hyperscan API call.
    ///
    /// A separate scratch region, allocated with hs_alloc_scratch() or hs_clone_scratch(), is
    /// required for every concurrent caller of the Hyperscan API.
    ///
    /// For example, this error might be returned when hs_scan() has been called inside a callback
    /// delivered by a currently-executing hs_scan() call using the same scratch region.
    ///
    /// Note: Not all concurrent uses of scratch regions may be detected. This error is intended
    /// as a best-effort debugging tool, not a guarantee.
    pub const SCRATCH_IN_USE: Self = Self(hs::HS_SCRATCH_IN_USE);
    /// Unsupported CPU architecture.
    ///
    /// This error is returned when Hyperscan is able to detect that the current system
    /// does not support the required instruction set.
    pub const ARCH_ERROR: Self = Self(hs::HS_ARCH_ERROR);
    /// The provided buffer was too small.
    ///
    /// This error indicates that there was insufficient space in the buffer. The call should be
    /// repeated with a larger provided buffer.
    ///
    /// Note: in this situation, it is normal for the amount of space required to be returned in
    /// the same manner as the used space would have been returned if the call was successful.
    pub const INSUFFICIENT_SPACE: Self = Self(hs::HS_INSUFFICIENT_SPACE);
    /// Unexpected internal error.
    ///
    /// This error indicates that there was unexpected matching behaviors. This could be related
    /// to invalid usage of stream and scratch space or invalid memory operations by users.
    pub const HS_UNKNOWN_ERROR: Self = Self(hs::HS_UNKNOWN_ERROR);
}

impl Display for ErrorCode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}({})",
            match *self {
                Self::SUCCESS => "SUCCESS",
                Self::INVALID => "INVALID",
                Self::NO_MEM => "NO_MEM",
                Self::SCAN_TERMINATED => "SCAN_TERMINATED",
                Self::COMPILER_ERROR => "COMPILER_ERROR",
                Self::DB_VERSION_ERROR => "DB_VERSION_ERROR",
                Self::DB_PLATFORM_ERROR => "DB_PLATFORM_ERROR",
                Self::DB_MODE_ERROR => "DB_MODE_ERROR",
                Self::BAD_ALIGN => "BAD_ALIGN",
                Self::BAD_ALLOC => "BAD_ALLOC",
                Self::SCRATCH_IN_USE => "SCRATCH_IN_USE",
                Self::ARCH_ERROR => "ARCH_ERROR",
                Self::INSUFFICIENT_SPACE => "INSUFFICIENT_SPACE",
                Self::HS_UNKNOWN_ERROR => "HS_UNKNOWN_ERROR",
                // Hyperscan will never send us anything different than the above constants
                _ => unreachable!(),
            },
            self.0
        )
    }
}

impl From<ErrorCode> for hs::hs_error_t {
    fn from(value: ErrorCode) -> hs::hs_error_t {
        value.0
    }
}

impl From<hs::hs_error_t> for ErrorCode {
    fn from(value: hs::hs_error_t) -> Self {
        Self(value)
    }
}
