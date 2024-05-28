// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use deno_core::v8;
use deno_core::v8::HandleScope;
use std::fmt::Debug;

#[derive(Debug, thiserror::Error)]
pub enum DDSAJsRuntimeError {
    #[error("expected `{name}` to exist within the v8 context")]
    VariableNotFound { name: String },
    #[error("type should be \"{expected}\", not \"{got}\"")]
    WrongType {
        expected: &'static str,
        got: &'static str,
    },
    /// A (shorthand) generic error used to fail a test. The test itself will have the appropriate context.
    #[cfg(test)]
    #[error("cfg(test): unspecified")]
    Unspecified,
}

/// Loads a global [`v8::Function`] from the provided scope, returning an error if either the
/// identifier doesn't exist, or if it doesn't refer to a function.
pub fn load_function(
    scope: &mut HandleScope,
    identifier: &str,
) -> Result<v8::Global<v8::Function>, DDSAJsRuntimeError> {
    let ctx = scope.get_current_context();
    let global = ctx.global(scope);

    let s_func_name = v8_interned(scope, identifier);
    let id_value = global.get(scope, s_func_name.into()).ok_or_else(|| {
        DDSAJsRuntimeError::VariableNotFound {
            name: identifier.to_string(),
        }
    })?;
    let func = v8::Local::<v8::Function>::try_from(id_value).map_err(|_| {
        DDSAJsRuntimeError::WrongType {
            expected: "function",
            got: id_value.type_repr(),
        }
    })?;
    Ok(v8::Global::new(scope, func))
}

/// Creates a [`Internalized`](v8::string::NewStringType::Internalized) v8 string. There is
/// extra runtime cost to this.
///
/// # Panics
/// Panics if `str` is longer than the v8 string length limit.
pub fn v8_interned<'s>(scope: &mut HandleScope<'s>, str: &str) -> v8::Local<'s, v8::String> {
    v8::String::new_from_one_byte(scope, str.as_bytes(), v8::NewStringType::Internalized)
        .expect("str length should be less than v8 limit")
}

/// Creates a [`Normal`](v8::string::NewStringType::Normal) v8 string, which always allocates memory
/// to create the string, even if it's been seen by the runtime before.
///
/// # Panics
/// Panics if `str` is longer than the v8 string length limit.
pub fn v8_string<'s>(scope: &mut HandleScope<'s>, str: &str) -> v8::Local<'s, v8::String> {
    v8::String::new_from_one_byte(scope, str.as_bytes(), v8::NewStringType::Normal)
        .expect("str length should be less than v8 limit")
}

/// A shorthand for creating a [`v8::Integer`].
pub fn v8_uint<'s>(scope: &mut HandleScope<'s>, number: u32) -> v8::Local<'s, v8::Integer> {
    v8::Integer::new_from_unsigned(scope, number)
}
