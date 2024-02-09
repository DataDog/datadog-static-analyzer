// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::compiler::error::HsCompileError;
use crate::compiler::CompileError;
use crate::runtime::ErrorCode;
use vectorscan_sys::hs;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("call returned error: {0}")]
    Runtime(ErrorCode),
    #[error("compile error: {0}")]
    Compile(#[from] CompileError),
    #[error("invalid C string: {0}")]
    NulChar(#[from] std::ffi::NulError),
}

/// Checks the return values from a Hyperscan FFI call, constructing an Err if required.
pub(crate) fn check_ffi_result(
    code: hs::hs_error_t,
    compile_error: Option<HsCompileError>,
) -> Result<(), Error> {
    let code: ErrorCode = code.into();
    match code {
        // `hs_error` is always returned regardless of success or failure, and code 0 represents success.
        ErrorCode::SUCCESS => Ok(()),
        ErrorCode::COMPILER_ERROR => {
            let compile_error =
                compile_error.expect("caller should have passed Some compile_error");
            // Safety: Hyperscan only sends `COMPILER_ERROR` after it has initialized `hs_compile_error`.
            let ffi_compile_error = unsafe { *compile_error.as_ptr() };
            let err = CompileError::new_from_ffi_error(ffi_compile_error);
            Err(Error::Compile(err))
        }
        _ => Err(Error::Runtime(code)),
    }
}
