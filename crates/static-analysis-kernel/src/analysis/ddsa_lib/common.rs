// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use deno_core::v8;
use deno_core::v8::HandleScope;
use std::fmt::Debug;
use std::ops::Deref;
use std::time::Duration;

/// A unique `u32` id used to identify a tree-sitter node sent from Rust to v8.
pub type NodeId = u32;

#[derive(Debug, thiserror::Error)]
pub enum DDSAJsRuntimeError {
    #[error("execution error: {reason}")]
    Execution { reason: String },
    #[error("JavaScript execution timeout")]
    JavaScriptTimeout { timeout: Duration },
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
    #[error("unable to interpret JavaScript: `{reason}`")]
    Interpreter { reason: String },
    /// A (shorthand) generic error used to fail a test. The test itself will have the appropriate context.
    #[cfg(test)]
    #[error("cfg(test): unspecified")]
    Unspecified,
}

/// A zero-size type marker indicating that the associated struct represents a JavaScript ES6 class object.
/// This is only used to improve code readability (it's not used to implement the Typestate pattern).
#[derive(Debug, Copy, Clone, Default, Eq, PartialEq, Hash)]
pub struct Class;
/// A zero-size type marker indicating that the associated struct represents an _instance_ of a JavaScript ES6 class.
/// This is only used to improve code readability (it's not used to implement the Typestate pattern).
#[derive(Debug, Copy, Clone, Default, Eq, PartialEq, Hash)]
pub struct Instance;

/// A newtype wrapper that provides a hook to alter behavior to provide backward compability with the
/// old `stella` library. This implements [`Deref`] for `T`.
pub struct StellaCompat<T>(T);

impl<T> StellaCompat<T> {
    pub fn new(inner: T) -> Self {
        Self(inner)
    }
}

impl<T> From<T> for StellaCompat<T> {
    fn from(value: T) -> Self {
        Self::new(value)
    }
}

impl<T> Deref for StellaCompat<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
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

/// Sets a [`v8::Global`] object's property to undefined.
pub fn set_undefined(
    object: &v8::Global<v8::Object>,
    scope: &mut HandleScope,
    key: &v8::Global<v8::String>,
) {
    let v8_object = object.open(scope);
    let key = v8::Local::new(scope, key);
    if v8_object
        .get(scope, key.into())
        .is_some_and(|value| !value.is_undefined())
    {
        let undefined = v8::undefined(scope);
        v8_object.set(scope, key.into(), undefined.into());
    }
}

/// Sets a [`v8::Global`] object's key to the value returned by the `value_generator`.
pub fn set_key_value<G>(
    object: &v8::Global<v8::Object>,
    scope: &mut HandleScope,
    key: &v8::Global<v8::String>,
    value_generator: G,
) where
    for<'s> G: Fn(&mut HandleScope<'s>) -> v8::Local<'s, v8::Value>,
{
    let v8_object = object.open(scope);
    let v8_key = v8::Local::new(scope, key);
    let v8_value = value_generator(scope);
    v8_object.set(scope, v8_key.into(), v8_value);
}

/// Creates a `v8::Global` [`UnboundScript`](v8::UnboundScript) from the given code.
pub fn compile_script(
    scope: &mut HandleScope,
    code: &str,
) -> Result<v8::Global<v8::UnboundScript>, DDSAJsRuntimeError> {
    let code_str = v8_string(scope, code);
    let tc_scope = &mut v8::TryCatch::new(scope);
    let script_result = v8::Script::compile(tc_scope, code_str, None);

    let script = script_result.ok_or_else(|| {
        let exception = tc_scope
            .exception()
            .expect("return value should only be `None` if an error was caught");
        let reason = exception.to_rust_string_lossy(tc_scope);
        tc_scope.reset();
        DDSAJsRuntimeError::Interpreter { reason }
    })?;

    let unbound_script = script.get_unbound_script(tc_scope);
    Ok(v8::Global::new(tc_scope, unbound_script))
}

#[cfg(test)]
mod tests {
    use crate::analysis::ddsa_lib::common::{compile_script, DDSAJsRuntimeError};
    use crate::analysis::ddsa_lib::JsRuntime;

    #[test]
    fn compile_script_invalid() {
        let mut runtime = JsRuntime::try_new().unwrap();
        let invalid_js = r#"
const invalidSyntax = const;
"#;
        let err = compile_script(&mut runtime.v8_handle_scope(), invalid_js).unwrap_err();
        let DDSAJsRuntimeError::Interpreter { reason } = err else {
            panic!("error variant should be `Interpreter`");
        };
        assert_eq!(reason, "SyntaxError: Unexpected token 'const'");
    }

    #[test]
    fn compile_script_valid() {
        let mut runtime = JsRuntime::try_new().unwrap();
        let invalid_js = r#"
const validSyntax = 123;
"#;
        assert!(compile_script(&mut runtime.v8_handle_scope(), invalid_js).is_ok());
    }
}
