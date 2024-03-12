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

unsafe impl Send for Scratch {}

impl Scratch {
    /// Allocate a new scratch space for use by a [BlockDatabase]. Hyperscan internally uses this function
    /// to do validity checks on the database.
    pub fn try_new_for(database: &BlockDatabase) -> Result<Self, Error> {
        let mut hs_scratch: *mut hs::hs_scratch_t = std::ptr::null_mut();
        let hs_error = unsafe { hs::hs_alloc_scratch(database.as_ptr(), &mut hs_scratch) };
        check_ffi_result(hs_error, None)?;
        Ok(Self(unsafe { NonNull::new_unchecked(hs_scratch) }))
    }

    /// Tries to allocate a clone of this scratch space.
    pub fn try_clone(&self) -> Result<Self, Error> {
        let mut cloned_scratch: *mut hs::hs_scratch_t = std::ptr::null_mut();
        let hs_error = unsafe { hs::hs_clone_scratch(self.0.as_ptr(), &mut cloned_scratch) };
        check_ffi_result(hs_error, None)?;

        // Safety: If Hyperscan didn't return an error, it initialized the pointer we provided.
        Ok(Self(unsafe { NonNull::new_unchecked(cloned_scratch) }))
    }

    // Returns the size in bytes of this scratch space.
    pub fn size(&self) -> Result<usize, Error> {
        let scratch_size = &mut 0_usize;
        let hs_error = unsafe { hs::hs_scratch_size(self.0.as_ptr(), &mut *scratch_size) };

        check_ffi_result(hs_error, None)?;
        Ok(*scratch_size)
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

impl Clone for Scratch {
    /// Clones the scratch space via an FFI call.
    ///
    /// # Panics
    /// Panics if the FFI call fails. This will only occur if the underlying allocator is either:
    /// * Unable to allocate memory (e.g. out of memory)
    /// * Allocates memory unaligned with a `unsigned long long` (i.e. the platform's largest datatype)
    fn clone(&self) -> Self {
        self.try_clone()
            .expect("hyperscan should be able to clone an existing scratch space")
    }
}

#[cfg(test)]
mod tests {
    use crate::database::BlockDatabase;
    use crate::{Pattern, Scratch};

    /// Tests the FFI call to [`hs::hs_scratch_size`](vectorscan_sys::hs::hs_scratch_size)
    #[test]
    fn scratch_size() {
        let pattern = Pattern::new("abc+").build();
        let db = BlockDatabase::try_new([&pattern]).unwrap();
        let scratch = Scratch::try_new_for(&db).unwrap();
        let size = scratch.size().unwrap();

        assert!(size > 0);
    }

    /// Tests the FFI call to [`hs::hs_clone_scratch`](vectorscan_sys::hs::hs_clone_scratch)
    #[test]
    fn clone_scratch() {
        let pattern = Pattern::new("abc+").build();
        let db = BlockDatabase::try_new([&pattern]).unwrap();
        let scratch = Scratch::try_new_for(&db).unwrap();
        let cloned = scratch.try_clone().unwrap();

        assert_eq!(scratch.size().unwrap(), cloned.size().unwrap());
    }
}
