// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::analysis::ddsa_lib::common::{
    expecting_var, get_field, get_optional_field, v8_type_from, DDSAJsRuntimeError,
};
use crate::analysis::ddsa_lib::v8_ds::V8Converter;
use crate::model::common::Position;
use crate::model::violation;
use deno_core::v8;
use deno_core::v8::HandleScope;

/// An intermediate representation of a JavaScript `Edit` class instance associated with a `Fix`.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum EditInstance {
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

impl EditInstance {
    pub const CLASS_NAME: &'static str = "Edit";
}

impl From<EditInstance> for violation::Edit {
    #[rustfmt::skip]
    fn from(value: EditInstance) -> Self {
        match value {
            EditInstance::Add { start_line, start_col, content } => {
                violation::Edit {
                    start: Position { line: start_line, col: start_col },
                    end: None,
                    edit_type: violation::EditType::Add,
                    content: Some(content),
                }
            },
            EditInstance::Remove { start_line, start_col, end_line, end_col} => {
                violation::Edit {
                    start: Position { line: start_line, col: start_col },
                    end: Some(Position { line: end_line, col: end_col }),
                    edit_type: violation::EditType::Remove,
                    content: None,
                }
            },
            EditInstance::Update { start_line, start_col, end_line, end_col, content} => {
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

/// A struct that can convert a [`v8::Value`] into an [`EditInstance`].
#[derive(Debug)]
pub(crate) struct EditConverter;

impl EditConverter {
    pub fn new() -> Self {
        Self
    }
}

impl V8Converter for EditConverter {
    type Item = EditInstance;
    type Error = DDSAJsRuntimeError;

    fn try_convert_from<'s>(
        &self,
        scope: &mut HandleScope<'s>,
        value: v8::Local<'s, v8::Value>,
    ) -> Result<Self::Item, Self::Error> {
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
                Ok(EditInstance::Add {
                    start_line,
                    start_col,
                    content,
                })
            }
            "REMOVE" => {
                let end_line = expecting_var(end_line, "endLine")?;
                let end_col = expecting_var(end_col, "endCol")?;
                Ok(EditInstance::Remove {
                    start_line,
                    start_col,
                    end_line,
                    end_col,
                })
            }
            "UPDATE" => {
                let end_line = expecting_var(end_line, "endLine")?;
                let end_col = expecting_var(end_col, "endCol")?;
                let content = expecting_var(content, "content")?;
                Ok(EditInstance::Update {
                    start_line,
                    start_col,
                    end_line,
                    end_col,
                    content,
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
    use crate::analysis::ddsa_lib::js::EditInstance;
    use crate::analysis::ddsa_lib::test_utils::{js_class_eq, js_instance_eq};

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
        assert!(js_instance_eq(EditInstance::CLASS_NAME, instance_expected));
        let class_expected = &["newAdd", "newRemove", "newUpdate"];
        assert!(js_class_eq(EditInstance::CLASS_NAME, class_expected));
    }
}
