// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use std::ffi::{CString, NulError};

/// A helper trait to improve the ergonomics for library consumers by allowing them
/// to only worry about passing in Rust-native string-like variables to library functions without
/// having to explicitly handle the conversion. This trait is inspired by an [upstream proposal].
///
/// [upstream proposal]: https://github.com/rust-lang/rust/issues/71448
pub trait TryToCString {
    fn try_to_cstring(&self) -> Result<CString, NulError>;
}

impl TryToCString for String {
    fn try_to_cstring(&self) -> Result<CString, NulError> {
        CString::new(self.clone().into_bytes())
    }
}
impl TryToCString for &String {
    fn try_to_cstring(&self) -> Result<CString, NulError> {
        CString::new(self.to_string().into_bytes())
    }
}

impl TryToCString for &str {
    fn try_to_cstring(&self) -> Result<CString, NulError> {
        CString::new(self.to_string().into_bytes())
    }
}
