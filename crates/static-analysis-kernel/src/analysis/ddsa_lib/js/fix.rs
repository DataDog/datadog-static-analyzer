// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::analysis::ddsa_lib::common::{
    get_field, iter_v8_array, v8_type_from, DDSAJsRuntimeError,
};
use crate::analysis::ddsa_lib::js::edit::{EditConverter, EditInstance};
use crate::analysis::ddsa_lib::v8_ds::V8Converter;
use crate::model::violation;
use deno_core::v8;
use deno_core::v8::HandleScope;

/// The JavaScript representation of a fix for a rule violation.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct FixInstance {
    pub message: String,
    pub edits: Vec<EditInstance>,
}

impl FixInstance {
    pub const CLASS_NAME: &'static str = "Fix";
}

impl From<FixInstance> for violation::Fix {
    fn from(value: FixInstance) -> Self {
        let description = value.message;
        let edits = value
            .edits
            .into_iter()
            .map(violation::Edit::from)
            .collect::<Vec<_>>();
        violation::Fix { description, edits }
    }
}

#[derive(Debug)]
pub(crate) struct FixConverter {
    edit_converter: EditConverter,
}

impl FixConverter {
    pub fn new() -> Self {
        let edit_converter = EditConverter::new();
        Self { edit_converter }
    }
}

impl V8Converter for FixConverter {
    type Item = FixInstance;
    type Error = DDSAJsRuntimeError;

    fn try_convert_from<'s>(
        &self,
        scope: &mut HandleScope<'s>,
        value: v8::Local<'s, v8::Value>,
    ) -> Result<Self::Item, Self::Error> {
        let v8_obj = v8_type_from::<v8::Object>(value, "instanceof Fix")?;
        let message = get_field::<v8::String>(v8_obj, "message", scope, "string")?
            .to_rust_string_lossy(scope);
        let edits = get_field::<v8::Array>(v8_obj, "edits", scope, "array")?;
        let edits = iter_v8_array(edits, scope)
            .map(|value| self.edit_converter.try_convert_from(scope, value))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(FixInstance { message, edits })
    }
}

#[cfg(test)]
mod tests {
    use crate::analysis::ddsa_lib::js::FixInstance;
    use crate::analysis::ddsa_lib::test_utils::{js_class_eq, js_instance_eq};

    #[test]
    fn js_properties_canary() {
        let instance_expected = &[
            // Variables
            "message", "edits",
        ];
        assert!(js_instance_eq(FixInstance::CLASS_NAME, instance_expected));
        let class_expected = &["new"];
        assert!(js_class_eq(FixInstance::CLASS_NAME, class_expected));
    }
}
