// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::analysis::ddsa_lib::common::{get_field, v8_type_from, DDSAJsRuntimeError, Instance};
use crate::analysis::ddsa_lib::v8_ds::V8Converter;
use common::model::position;
use deno_core::v8;
use deno_core::v8::HandleScope;
use std::marker::PhantomData;

/// A representation of a JavaScript `CodeRegion` class instance.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct CodeRegion<T> {
    pub start_line: u32,
    pub start_col: u32,
    pub end_line: u32,
    pub end_col: u32,
    /// (See documentation on [`Instance`]).
    pub _pd: PhantomData<T>,
}

impl CodeRegion<Instance> {
    pub const CLASS_NAME: &'static str = "CodeRegion";
}

impl<T> From<CodeRegion<T>> for position::Region {
    fn from(value: CodeRegion<T>) -> Self {
        Self {
            start: position::Position {
                line: value.start_line,
                col: value.start_col,
            },
            end: position::Position {
                line: value.end_line,
                col: value.end_col,
            },
        }
    }
}

/// A struct that can convert a [`v8::Value`] to a [`CodeRegion`].
#[derive(Debug)]
pub(crate) struct CodeRegionConverter;

impl CodeRegionConverter {
    pub fn new() -> Self {
        Self
    }
}

impl V8Converter for CodeRegionConverter {
    type Item = CodeRegion<Instance>;
    type Error = DDSAJsRuntimeError;

    fn try_convert_from<'s>(
        &self,
        scope: &mut HandleScope<'s>,
        value: v8::Local<'s, v8::Value>,
    ) -> Result<Self::Item, Self::Error> {
        let v8_obj = v8_type_from::<v8::Object>(value, "an object")?;
        let start_line =
            get_field::<v8::Integer>(v8_obj, "startLine", scope, "number")?.value() as u32;
        let start_col =
            get_field::<v8::Integer>(v8_obj, "startCol", scope, "number")?.value() as u32;
        let end_line = get_field::<v8::Integer>(v8_obj, "endLine", scope, "number")?.value() as u32;
        let end_col = get_field::<v8::Integer>(v8_obj, "endCol", scope, "number")?.value() as u32;
        Ok(CodeRegion {
            start_line,
            start_col,
            end_line,
            end_col,
            _pd: PhantomData,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::analysis::ddsa_lib::js::CodeRegion;
    use crate::analysis::ddsa_lib::test_utils::{js_class_eq, js_instance_eq};

    #[test]
    fn js_properties_canary() {
        let instance_exp = &[
            // Variables
            "startLine",
            "startCol",
            "endLine",
            "endCol",
        ];
        assert!(js_instance_eq(CodeRegion::CLASS_NAME, instance_exp));
        let class_expected = &[];
        assert!(js_class_eq(CodeRegion::CLASS_NAME, class_expected));
    }
}
