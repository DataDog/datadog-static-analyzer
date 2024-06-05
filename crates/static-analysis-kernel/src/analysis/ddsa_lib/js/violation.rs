// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::analysis::ddsa_lib::common::{
    get_field, get_optional_field, iter_v8_array, v8_type_from, DDSAJsRuntimeError, Instance,
};
use crate::analysis::ddsa_lib::js::fix::{Fix, FixConverter};
use crate::analysis::ddsa_lib::v8_ds::V8Converter;
use crate::model::common::Position;
use crate::model::rule::{RuleCategory, RuleSeverity};
use crate::model::violation;
use deno_core::v8;
use deno_core::v8::HandleScope;
use std::marker::PhantomData;

/// A representation of a JavaScript `Violation` class instance.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Violation<T> {
    pub start_line: u32,
    pub start_col: u32,
    pub end_line: u32,
    pub end_col: u32,
    pub message: String,
    pub fixes: Option<Vec<Fix<T>>>,
    pub _pd: PhantomData<T>,
}

impl Violation<Instance> {
    pub const CLASS_NAME: &'static str = "Violation";

    /// Converts this into a [`violation::Violation`] with the given severity and category.
    pub fn into_violation(
        self,
        severity: RuleSeverity,
        category: RuleCategory,
    ) -> violation::Violation {
        let fixes = self
            .fixes
            .map(|fixes| fixes.into_iter().map(violation::Fix::from).collect())
            .unwrap_or_default();
        violation::Violation {
            start: Position {
                line: self.start_line,
                col: self.start_col,
            },
            end: Position {
                line: self.end_line,
                col: self.end_col,
            },
            message: self.message,
            severity,
            category,
            fixes,
        }
    }
}

pub(crate) struct ViolationConverter {
    fix_converter: FixConverter,
}

impl ViolationConverter {
    pub fn new() -> Self {
        let fix_converter = FixConverter::new();
        Self { fix_converter }
    }
}

impl V8Converter for ViolationConverter {
    type Item = Violation<Instance>;
    type Error = DDSAJsRuntimeError;

    fn try_convert_from<'s>(
        &self,
        scope: &mut HandleScope<'s>,
        value: v8::Local<'s, v8::Value>,
    ) -> Result<Self::Item, Self::Error> {
        let v8_obj = v8_type_from::<v8::Object>(value, "instanceof Violation")?;
        let start_line =
            get_field::<v8::Integer>(v8_obj, "startLine", scope, "number")?.value() as u32;
        let start_col =
            get_field::<v8::Integer>(v8_obj, "startCol", scope, "number")?.value() as u32;
        let end_line = get_field::<v8::Integer>(v8_obj, "endLine", scope, "number")?.value() as u32;
        let end_col = get_field::<v8::Integer>(v8_obj, "endCol", scope, "number")?.value() as u32;
        let message = get_field::<v8::String>(v8_obj, "message", scope, "string")?
            .to_rust_string_lossy(scope);
        let fixes = get_optional_field::<v8::Array>(v8_obj, "fixes", scope, "array | undefined")?;
        let fixes = fixes
            .map(|array| {
                iter_v8_array(array, scope)
                    .map(|value| self.fix_converter.try_convert_from(scope, value))
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?;
        Ok(Violation {
            start_line,
            start_col,
            end_line,
            end_col,
            message,
            fixes,
            _pd: PhantomData,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::analysis::ddsa_lib::js::Violation;
    use crate::analysis::ddsa_lib::test_utils::{js_class_eq, js_instance_eq};

    #[test]
    fn js_properties_canary() {
        let instance_exp = &[
            // Variables
            "startLine",
            "startCol",
            "endLine",
            "endCol",
            "message",
            "fixes",
            // Methods
            "addFix",
        ];
        assert!(js_instance_eq(Violation::CLASS_NAME, instance_exp));
        let class_expected = &["new"];
        assert!(js_class_eq(Violation::CLASS_NAME, class_expected));
    }
}
