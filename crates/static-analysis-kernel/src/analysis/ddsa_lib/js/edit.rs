// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::analysis::ddsa_lib::common::{
    expecting_var, get_field, get_optional_field, v8_type_from, DDSAJsRuntimeError, Instance,
};
use crate::analysis::ddsa_lib::v8_ds::V8Converter;
use crate::model::violation;
use common::model::position::Position;
use deno_core::v8;
use deno_core::v8::HandleScope;
use std::marker::PhantomData;

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Edit<T> {
    pub kind: EditKind,
    /// (See documentation on [`Instance`]).
    _pd: PhantomData<T>,
}

/// An intermediate representation of a JavaScript `Edit` class instance associated with a `Fix`.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum EditKind {
    Add {
        start_line: u32,
        start_col: u32,
        content: String,
    },
    Remove {
        start_line: u32,
        start_col: u32,
        end_line: u32,
        end_col: u32,
    },
    Update {
        start_line: u32,
        start_col: u32,
        end_line: u32,
        end_col: u32,
        content: String,
    },
}

impl Edit<Instance> {
    pub const CLASS_NAME: &'static str = "Edit";
}

impl<T> From<Edit<T>> for violation::Edit {
    #[rustfmt::skip]
    fn from(value: Edit<T>) -> Self {
        match value.kind {
            EditKind::Add { start_line, start_col, content } => {
                violation::Edit {
                    start: Position { line: start_line, col: start_col },
                    end: None,
                    edit_type: violation::EditType::Add,
                    content: Some(content),
                }
            },
            EditKind::Remove { start_line, start_col, end_line, end_col} => {
                violation::Edit {
                    start: Position { line: start_line, col: start_col },
                    end: Some(Position { line: end_line, col: end_col }),
                    edit_type: violation::EditType::Remove,
                    content: None,
                }
            },
            EditKind::Update { start_line, start_col, end_line, end_col, content} => {
                violation::Edit {
                    start: Position { line: start_line, col: start_col },
                    end: Some(Position { line: end_line, col: end_col }),
                    edit_type: violation::EditType::Update,
                    content: Some(content),
                }
            },
        }
    }
}

/// A struct that can convert a [`v8::Value`] into an [`Edit`].
#[derive(Debug)]
pub(crate) struct EditConverter;

impl EditConverter {
    pub fn new() -> Self {
        Self
    }
}

impl V8Converter for EditConverter {
    type Item = Edit<Instance>;
    type Error = DDSAJsRuntimeError;

    fn try_convert_from<'s>(
        &self,
        scope: &mut HandleScope<'s>,
        value: v8::Local<'s, v8::Value>,
    ) -> Result<Self::Item, Self::Error> {
        let _pd = PhantomData;
        // NOTE: We don't cache the field names here purely for simplicity.
        let v8_obj = v8_type_from::<v8::Object>(value, "object")?;
        let edit_type =
            get_field::<v8::String>(v8_obj, "kind", scope, "string")?.to_rust_string_lossy(scope);
        let start_line =
            get_field::<v8::Integer>(v8_obj, "startLine", scope, "number")?.value() as u32;
        let start_col =
            get_field::<v8::Integer>(v8_obj, "startCol", scope, "number")?.value() as u32;
        let end_line = get_optional_field::<v8::Integer>(v8_obj, "endLine", scope, "number")?
            .map(|v| v.value() as u32);
        let end_col = get_optional_field::<v8::Integer>(v8_obj, "endCol", scope, "number")?
            .map(|v| v.value() as u32);
        let content = get_optional_field::<v8::String>(v8_obj, "content", scope, "number")?
            .map(|v| v.to_rust_string_lossy(scope));

        match edit_type.as_str() {
            "ADD" => {
                let content = expecting_var(content, "content")?;
                Ok(Edit {
                    kind: EditKind::Add {
                        start_line,
                        start_col,
                        content,
                    },
                    _pd,
                })
            }
            "REMOVE" => {
                let end_line = expecting_var(end_line, "endLine")?;
                let end_col = expecting_var(end_col, "endCol")?;
                Ok(Edit {
                    kind: EditKind::Remove {
                        start_line,
                        start_col,
                        end_line,
                        end_col,
                    },
                    _pd,
                })
            }
            "UPDATE" => {
                let end_line = expecting_var(end_line, "endLine")?;
                let end_col = expecting_var(end_col, "endCol")?;
                let content = expecting_var(content, "content")?;
                Ok(Edit {
                    kind: EditKind::Update {
                        start_line,
                        start_col,
                        end_line,
                        end_col,
                        content,
                    },
                    _pd,
                })
            }
            _ => Err(DDSAJsRuntimeError::InvalidValue {
                identifier: "kind",
                expected: "one of `ADD`, `REMOVE`, `UPDATE`",
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::analysis::ddsa_lib::common::{DDSAJsRuntimeError, Instance};
    use crate::analysis::ddsa_lib::js::{Edit, EditConverter, EditKind};
    use crate::analysis::ddsa_lib::test_utils::{
        cfg_test_runtime, js_class_eq, js_instance_eq, try_execute,
    };
    use crate::analysis::ddsa_lib::v8_ds::V8Converter;
    use deno_core::v8::HandleScope;
    use std::marker::PhantomData;

    #[rustfmt::skip]
    fn assert_de_ok(input: &str, s: &mut HandleScope) {
        let c = EditConverter::new();
        assert!(try_execute(s, input).is_ok_and(|v| c.try_convert_from(s, v).is_ok()));
    }
    #[rustfmt::skip]
    fn assert_de_fail(input: &str, scope: &mut HandleScope, expected: &str) {
        let c = EditConverter::new();
        assert!(try_execute(scope, input).is_ok_and(|v| {
            let err = c.try_convert_from(scope, v).unwrap_err();
            match expected {
                "NotFound" => { matches!(err, DDSAJsRuntimeError::VariableNotFound { .. })}
                "WrongType" => { matches!(err, DDSAJsRuntimeError::WrongType { .. })}
                "InvalidValue" => { matches!(err, DDSAJsRuntimeError::InvalidValue { .. })}
                _ => unreachable!()
            }
        }));
    }

    #[test]
    fn js_properties_canary() {
        let instance_expected = &[
            // Variables
            "startLine",
            "startCol",
            "endLine",
            "endCol",
            "kind",
            "content",
        ];
        assert!(js_instance_eq(Edit::CLASS_NAME, instance_expected));
        let class_expected = &["newAdd", "newRemove", "newUpdate"];
        assert!(js_class_eq(Edit::CLASS_NAME, class_expected));
    }

    /// Simple smoke test for deserialization
    #[rustfmt::skip]
    #[test]
    fn edit_converter_deserialization() {
        let mut runtime = cfg_test_runtime();
        let s = &mut runtime.handle_scope();
        // Users should not be creating `Edit` instances via the constructor, it's tested regardless
        // Missing `startCol`
        assert_de_fail("new Edit(10, undefined, undefined, undefined, 'ADD', 'More text')", s, "NotFound");
        // Missing `startLine`
        assert_de_ok("new Edit(10, 20, undefined, undefined, 'ADD', 'Additional')", s);
        assert_de_fail("new Edit(undefined, 20, undefined, undefined, 'ADD', 'More text')", s, "NotFound");

        // Static "constructors"
        // Add
        assert_de_ok("Edit.newAdd(10, 20, 'Additional')", s);
        assert_de_fail("Edit.newAdd(10, 'string_not_number', 'Additional')", s, "WrongType");
        // Remove
        assert_de_ok("Edit.newRemove(10, 20, 10, 30)", s);
        // JavaScript implicit `undefined` parameters (equivalent to `Edit.newRemove(10, 20, 10, undefined)`)
        assert_de_fail("Edit.newRemove(10, 20, 10)", s, "NotFound");
        // Update
        assert_de_ok("Edit.newUpdate(10, 20, 10, 31, 'Replacement')", s);

        // Incorrect `kind` string enum
        assert_de_ok("new Edit(10, 20, 10, 31, 'REMOVE')", s);
        assert_de_fail("new Edit(10, 20, 10, 31, 'DELETE')", s, "InvalidValue");
    }

    /// The `Edit` JavaScript class is not strictly validated upon creation (in JavaScript), allowing
    /// superfluous input. This should not cause a deserialization failure, as we are plucking
    /// specific fields, not deserializing the entire object. In practice, this should
    #[rustfmt::skip]
    #[test]
    fn edit_converter_deserialize_superfluous() {
        let mut runtime = cfg_test_runtime();
        let scope = &mut runtime.handle_scope();
        let mut deserialize = |input: &str| -> Edit<Instance> {
            let c = EditConverter::new();
            try_execute(scope, input).map(|v| c.try_convert_from(scope, v)).unwrap().unwrap()
        };
        let expected = Edit {
            kind: EditKind::Add {
                start_line: 10,
                start_col: 20,
                content: "More text".to_string(),
            },
            _pd: PhantomData,
        };
        // Extraneous `endLine`, `endCol`
        assert_eq!(deserialize("new Edit(10, 20, 1234, 4321, 'ADD', 'More text')"), expected.clone());
        // Extraneous fields on static methods
        assert_eq!(deserialize("Edit.newAdd(10, 20, 'More text', 1234, undefined, 4321)"), expected.clone());
    }
}
