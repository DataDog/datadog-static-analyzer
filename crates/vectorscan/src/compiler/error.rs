// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use core::ffi;
use std::ptr::NonNull;
use vectorscan_sys::hs;

/// Errors returned by the `compile` family of calls
#[derive(Debug, thiserror::Error)]
pub enum CompileError {
    /// An [`hs::hs_compile_error`] triggered by a pattern, containing both the message and the
    /// zero-based index of the pattern.
    #[error("pattern compilation error: `{message}` (index {pattern_index})")]
    Pattern { message: String, pattern_index: u32 },
    /// An [`hs::hs_compile_error`] not triggered by a pattern.
    #[error("compilation error: `{message}`")]
    General { message: String },
}

impl CompileError {
    /// Constructs a CompileError from a pointer to dynamic memory containing a [`hs::hs_compile_error`].
    /// This should be used after performing an FFI call to a function that generates this struct, such as:
    /// * [`hs::hs_compile`]
    /// * [`hs::hs_compile_multi`]
    /// * [`hs::hs_compile_ext_multi`]
    /// * [`hs::hs_compile_lit`]
    /// * [`hs::hs_compile_lit_multi`]
    ///
    //  This is implemented as an explicit function instead of a `From<hs::hs_compile_error_t>` impl
    //  to be clear about the FFI involved
    pub(crate) fn new_from_ffi_error(error: hs::hs_compile_error_t) -> CompileError {
        let cstr = unsafe { ffi::CStr::from_ptr(error.message) };
        let message = String::from_utf8_lossy(cstr.to_bytes()).to_string();

        // If `expression` is not negative, it represents the 0-based index of the pattern that caused the error.
        // If the error was not caused by a specific pattern, Hyperscan signals this with a negative number.
        // https://intel.github.io/hyperscan/dev-reference/api_files.html#c.hs_compile_error.expression
        if error.expression >= 0 {
            CompileError::Pattern {
                message,
                pattern_index: error.expression as u32,
            }
        } else {
            CompileError::General { message }
        }
    }
}

/// A wrapper around [`hs::hs_compile_error`] to handle freeing the memory.
#[derive(Debug)]
#[repr(transparent)]
pub(crate) struct HsCompileError(NonNull<hs::hs_compile_error_t>);

impl HsCompileError {
    /// Creates a new [`HsCompileError`] if `ptr` is not null.
    pub(crate) fn from_ptr(ptr: *mut hs::hs_compile_error_t) -> Option<Self> {
        NonNull::new(ptr).map(Self)
    }

    /// Acquires the underlying `*mut` pointer.
    pub(crate) fn as_ptr(&self) -> *mut hs::hs_compile_error_t {
        self.0.as_ptr()
    }
}

impl Drop for HsCompileError {
    fn drop(&mut self) {
        // Ignore `hs_error`
        // Safety: this is a `NonNull<T>` pointer.
        let _ = unsafe { hs::hs_free_compile_error(self.0.as_ptr()) };
    }
}
