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
    #[error("invalid value for `{identifier}`: expected {expected}")]
    InvalidValue {
        identifier: &'static str,
        expected: &'static str,
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

/// A shorthand for requiring that a v8 value be defined, otherwise an error is returned.
pub fn expecting_var<T>(value: Option<T>, name: &str) -> Result<T, DDSAJsRuntimeError> {
    value.ok_or_else(|| DDSAJsRuntimeError::VariableNotFound {
        name: name.to_string(),
    })
}

/// Takes a [`v8::Value`] and attempts to parse it as a [`T`], returning an error if the conversion is invalid.
///
/// NOTE: `expecting` is only used to provide a better `DDSAJsRuntimeError::WrongType` message, and so
/// it should be a human-friendly label for [`T`].
pub fn v8_type_from<'s, T>(
    value: v8::Local<'s, v8::Value>,
    expecting: &'static str,
) -> Result<v8::Local<'s, T>, DDSAJsRuntimeError>
where
    v8::Local<'s, v8::Value>: TryInto<v8::Local<'s, T>>,
{
    let as_ty: Result<v8::Local<T>, _> =
        value.try_into().map_err(|_| DDSAJsRuntimeError::WrongType {
            expected: expecting,
            got: value.type_repr(),
        });
    as_ty
}

/// Takes a [`v8::Object`] and looks up the provided field name, and attempts to convert the value
/// into the provided v8 type, returning an error if the conversion is invalid.
///
/// Note that this function is relatively slow, as it will create a new interned `v8::String` for the `field_name`.
pub fn get_field<'s, T>(
    value: v8::Local<v8::Object>,
    field_name: &'static str,
    scope: &mut HandleScope<'s>,
    expecting: &'static str,
) -> Result<v8::Local<'s, T>, DDSAJsRuntimeError>
where
    v8::Local<'s, v8::Value>: TryInto<v8::Local<'s, T>>,
{
    let value = get_optional_field(value, field_name, scope, expecting)?;
    value.ok_or_else(|| DDSAJsRuntimeError::VariableNotFound {
        name: field_name.to_string(),
    })
}

/// Takes a [`v8::Object`], looks up the provided field name, and attempts to convert the value
/// into the provided v8 type, returning an error if the conversion is invalid. Nullish values are
/// returned as `None`.
///
/// Note that this function is relatively slow, as it will create a new interned `v8::String` for the `field_name`.
pub fn get_optional_field<'s, T>(
    value: v8::Local<v8::Object>,
    field_name: &'static str,
    scope: &mut HandleScope<'s>,
    expecting: &'static str,
) -> Result<Option<v8::Local<'s, T>>, DDSAJsRuntimeError>
where
    v8::Local<'s, v8::Value>: TryInto<v8::Local<'s, T>>,
{
    let v8_field_name = v8_interned(scope, field_name);
    let field_value = value.get(scope, v8_field_name.into()).ok_or_else(|| {
        DDSAJsRuntimeError::VariableNotFound {
            name: field_name.to_string(),
        }
    })?;
    if field_value.is_null_or_undefined() {
        Ok(None)
    } else {
        v8_type_from(field_value, expecting).map(Some)
    }
}

/// Creates an iterator over a [`v8::Array`].
///
/// NOTE: this is not a zero-cost abstraction, as it first collects the entire v8 array into
/// a `Vec`, and then returns an iterator over that `Vec`.
pub fn iter_v8_array<'s>(
    value: v8::Local<'s, v8::Array>,
    scope: &mut HandleScope<'s>,
) -> impl Iterator<Item = v8::Local<'s, v8::Value>> {
    let len = value.length();
    let mut vec = Vec::with_capacity(len as usize);
    for idx in 0..len {
        vec.push(value.get_index(scope, idx).expect("index should exist"));
    }
    vec.into_iter()
}
