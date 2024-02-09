// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::compiler::error::HsCompileError;
use crate::compiler::Mode;
use crate::compiler::Pattern;
use crate::error::{check_ffi_result, Error};
use core::ffi;
use std::borrow::Borrow;
use std::ffi::CString;
use std::ptr;
use std::ptr::NonNull;
use vectorscan_sys::hs;

/// A wrapper struct to handle clean-up of the underlying [`hs::hs_database_t`]
#[derive(Debug)]
#[repr(transparent)]
pub(crate) struct DatabaseWrapper(NonNull<hs::hs_database_t>);

unsafe impl Send for DatabaseWrapper {}

unsafe impl Sync for DatabaseWrapper {}

impl DatabaseWrapper {
    pub(crate) fn as_ptr(&self) -> *mut hs::hs_database_t {
        self.0.as_ptr()
    }
    pub(crate) fn size(&self) -> Result<usize, Error> {
        let database_size = &mut 0_usize;
        let hs_error = unsafe { hs::hs_database_size(self.0.as_ptr(), &mut *database_size) };

        check_ffi_result(hs_error, None)?;
        Ok(*database_size)
    }
}

impl Drop for DatabaseWrapper {
    fn drop(&mut self) {
        // Ignore `hs_error`
        let _ = unsafe { hs::hs_free_database(self.0.as_ptr()) };
    }
}

impl DatabaseWrapper {
    pub(crate) fn try_new<'a, T>(
        patterns: impl IntoIterator<Item = T>,
        mode: Mode,
    ) -> Result<Self, Error>
    where
        T: Borrow<&'a Pattern>,
    {
        // Hyperscan has a "Struct of Arrays" API, as opposed to our "Array of Structs". Thus, we need to
        // split the values of each Pattern across four Vecs.
        let (mut c_strs, mut flags, mut ids, mut extensions) = (
            Vec::<CString>::new(),
            Vec::<ffi::c_uint>::new(),
            Vec::<ffi::c_uint>::new(),
            Vec::<hs::hs_expr_ext>::new(),
        );
        for pattern in patterns.into_iter().map(|p| *p.borrow()) {
            let c_str = pattern.to_c_string();
            c_strs.push(c_str);
            let flag_bits = pattern.flags().bits();
            flags.push(flag_bits);
            let id = pattern.id();
            ids.push(id);
            let ext = pattern.extensions().to_ffi();
            extensions.push(ext);
        }
        let patterns_len = c_strs.len();

        let c_str_ptrs: Vec<*const ffi::c_char> = c_strs.iter().map(|cs| cs.as_ptr()).collect();
        let ext_ptrs: Vec<*const hs::hs_expr_ext_t> = extensions
            .iter()
            .map(|ext| ext as *const hs::hs_expr_ext_t)
            .collect();
        let null_ptr = ptr::null();
        let mut hs_db: *mut hs::hs_database_t = ptr::null_mut();
        let mut hs_compile_error: *mut hs::hs_compile_error_t = ptr::null_mut();

        let hs_error = unsafe {
            hs::hs_compile_ext_multi(
                c_str_ptrs.as_ptr(),
                flags.as_ptr(),
                ids.as_ptr(),
                ext_ptrs.as_ptr(),
                patterns_len as ffi::c_uint,
                mode.bits(),
                // A null pointer instructs Hyperscan to build for the current platform.
                // Reference: https://intel.github.io/hyperscan/dev-reference/api_files.html
                null_ptr,
                &mut hs_db,
                &mut hs_compile_error,
            )
        };
        check_ffi_result(hs_error, HsCompileError::from_ptr(hs_compile_error))?;

        Ok(DatabaseWrapper(unsafe { NonNull::new_unchecked(hs_db) }))
    }
}

/// A database for scanning in [Block] mode
///
/// [Block]: https://intel.github.io/hyperscan/dev-reference/runtime.html#block-mode
#[derive(Debug)]
#[repr(transparent)]
pub struct BlockDatabase(DatabaseWrapper);

impl BlockDatabase {
    /// Constructs a new Hyperscan database.
    pub fn try_new<'a, T>(patterns: impl IntoIterator<Item = T>) -> Result<Self, Error>
    where
        T: Borrow<&'a Pattern>,
    {
        DatabaseWrapper::try_new(patterns, Mode::BLOCK).map(Self)
    }

    /// Provides the size of the given database in bytes.
    pub fn size(&self) -> Result<usize, Error> {
        self.0.size()
    }

    pub(crate) fn as_ptr(&self) -> *mut hs::hs_database_t {
        self.0.as_ptr()
    }
}
