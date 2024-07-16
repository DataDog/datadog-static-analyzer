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

/// Creates a [`Internalized`](v8::string::NewStringType::Internalized) v8 string. This incurs
/// an additional runtime cost (via v8 string hashing), however it prevents allocations of strings
/// that the v8 runtime has already seen before.
///
/// This should only be used for short ASCII strings that are known to be repeatedly used,
/// like object property names. For performance reasons, this should never be used for user-provided data.
///
/// # Panics
/// * Panics if the provided string is not ASCII.
/// * Panics if `str` is longer than the v8 string length limit.
pub fn v8_interned<'s>(scope: &mut HandleScope<'s>, str: &str) -> v8::Local<'s, v8::String> {
    // This is a debug assertion because `is_ascii()` is O(N), and the `v8_interned` function is called
    // frequently in performance-critical paths.
    debug_assert!(str.is_ascii(), "string must be ASCII");
    v8::String::new_from_one_byte(scope, str.as_bytes(), v8::NewStringType::Internalized)
        .expect("str length should be less than v8 limit")
}

/// Creates a [`Normal`](v8::string::NewStringType::Normal) v8 string, which always allocates memory
/// to create the string, even if it has been seen by the runtime before.
///
/// # Panics
/// Panics if `str` is longer than the v8 string length limit.
pub fn v8_string<'s>(scope: &mut HandleScope<'s>, str: &str) -> v8::Local<'s, v8::String> {
    v8::String::new_from_utf8(scope, str.as_bytes(), v8::NewStringType::Normal)
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

pub type V8DefaultContextMutateFn = dyn Fn(&mut HandleScope, v8::Local<v8::Context>);

/// Creates a [`deno_core::JsRuntime`] with the provided `extensions`.
///
/// If provided, a `config_default_v8_context` can configure the default `v8::Context`
/// that will be used as the base for all newly-created `v8::Context`s within the
/// runtime's `v8::Isolate`.
pub fn create_base_runtime(
    extensions: Vec<deno_core::Extension>,
    config_default_v8_context: Option<Box<V8DefaultContextMutateFn>>,
) -> deno_core::JsRuntime {
    if let Some(config_fn) = config_default_v8_context {
        // If a function is provided to configure the default v8::Context, first create a v8::Snapshot,
        // mutate the default context, and then create a new JsRuntime with that snapshot.
        let mut snapshot_runtime =
            deno_core::JsRuntimeForSnapshot::new(Default::default(), Default::default());
        {
            let scope = &mut snapshot_runtime.handle_scope();
            let default_ctx = scope.get_current_context();
            config_fn(scope, default_ctx);
        }
        let snapshot = snapshot_runtime.snapshot();
        deno_core::JsRuntime::new(deno_core::RuntimeOptions {
            extensions,
            startup_snapshot: Some(deno_core::Snapshot::JustCreated(snapshot)),
            ..Default::default()
        })
    } else {
        deno_core::JsRuntime::new(deno_core::RuntimeOptions {
            extensions,
            ..Default::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::analysis::ddsa_lib::common::{
        compile_script, create_base_runtime, v8_interned, v8_string, DDSAJsRuntimeError,
    };
    use crate::analysis::ddsa_lib::test_utils::{cfg_test_runtime, try_execute};
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

    /// Tests that `create_base_runtime` can modify the default v8::Context for the runtime's v8 isolate.
    #[test]
    fn create_base_runtime_mutate_ctx() {
        let mut runtime = create_base_runtime(vec![], None);
        // We use the ES6 `Map` constructor because it will always be present
        let code = "Map;";

        let value = try_execute(&mut runtime.handle_scope(), code).unwrap();
        assert!(value.is_object());

        let mut runtime = create_base_runtime(
            vec![],
            Some(Box::new(|scope, default_ctx| {
                let key = v8_interned(scope, "Map");
                let global_proxy = default_ctx.global(scope);
                global_proxy.delete(scope, key.into());
            })),
        );
        let value = try_execute(&mut runtime.handle_scope(), code).unwrap_err();
        assert_eq!(value, "ReferenceError: Map is not defined".to_string());
    }

    // One byte characters
    const ASCII: &str = "abc!";
    // One byte characters
    const LATIN_1_SUPPLEMENT: &str = "®±¶¿Ð";
    // Greater than one byte characters
    const WIDE: &str = "🌎";

    /// [`v8_string`] should be able to create strings utilizing the whole UTF-8 range.
    #[test]
    fn v8_string_fn_utf8() {
        let mut runtime = cfg_test_runtime();
        let scope = &mut runtime.handle_scope();

        // Round-trip the strings through v8 to ensure a lossless conversion.
        for (text, is_only_onebyte) in [(ASCII, true), (LATIN_1_SUPPLEMENT, true), (WIDE, false)] {
            let v8_str = v8_string(scope, text);
            assert_eq!(v8_str.contains_only_onebyte(), is_only_onebyte);
            // Despite the function name, in this case, it will be lossless because a String, by definition, is UTF-8.
            assert_eq!(v8_str.to_rust_string_lossy(scope), text);
        }
    }

    /// [`v8_interned`] should be able to create v8 "OneByte" strings from ASCII.
    #[test]
    fn v8_interned_fn_ascii() {
        let mut runtime = cfg_test_runtime();
        let scope = &mut runtime.handle_scope();

        let v8_str = v8_interned(scope, ASCII);
        assert!(v8_str.contains_only_onebyte());
        // Because we asserted `contains_only_onebyte` above, the below will not be a lossy conversion.
        assert_eq!(v8_str.to_rust_string_lossy(scope), ASCII);
    }

    /// [`v8_interned`] should panic if called with a non-ASCII string.
    #[test]
    fn v8_interned_fn_not_ascii() {
        for text in [LATIN_1_SUPPLEMENT, WIDE] {
            let result = std::panic::catch_unwind(|| {
                let mut runtime = cfg_test_runtime();
                let scope = &mut runtime.handle_scope();
                let _v8_str = v8_interned(scope, text);
            });
            assert!(result.is_err());
        }
    }
}
