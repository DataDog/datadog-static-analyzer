// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::database::BlockDatabase;
use crate::error::{check_ffi_result, Error};
use std::ptr::NonNull;
use vectorscan_sys::hs;

/// A large enough region of scratch space to support a given database.
///
/// This scratch space can be cloned, which is useful when multiple concurrent threads will be using the same
/// set of compiled databases, and another scratch space is required.
#[derive(Debug)]
#[repr(transparent)]
pub struct Scratch(NonNull<hs::hs_scratch>);

impl Scratch {
    /// Allocate a new scratch space for use by a [BlockDatabase]. Hyperscan internally uses this function
    /// to do validity checks on the database.
    pub fn try_new_for(database: &BlockDatabase) -> Result<Self, Error> {
        let mut hs_scratch: *mut hs::hs_scratch_t = std::ptr::null_mut();
        let hs_error = unsafe { hs::hs_alloc_scratch(database.as_ptr(), &mut hs_scratch) };
        check_ffi_result(hs_error, None)?;
        Ok(Self(unsafe { NonNull::new_unchecked(hs_scratch) }))
    }

    pub(crate) fn as_ptr(&self) -> *mut hs::hs_scratch {
        self.0.as_ptr()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        // Ignore `hs_error`
        let _ = unsafe { hs::hs_free_scratch(self.0.as_ptr()) };
    }
}
