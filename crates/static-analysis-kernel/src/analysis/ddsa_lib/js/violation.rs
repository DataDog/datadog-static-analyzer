// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::analysis::ddsa_lib::common::{
    get_field, get_optional_field, iter_v8_array, v8_type_from, DDSAJsRuntimeError, Instance,
};
use crate::analysis::ddsa_lib::js::fix::{Fix, FixConverter};
use crate::analysis::ddsa_lib::js::region::{CodeRegion, CodeRegionConverter};
use crate::analysis::ddsa_lib::v8_ds::V8Converter;
use crate::model::rule::{RuleCategory, RuleSeverity};
use crate::model::violation;
use common::model::position;
use deno_core::v8;
use deno_core::v8::HandleScope;
use std::marker::PhantomData;

/// A representation of a JavaScript `Violation` class instance.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Violation<T> {
    pub message: String,
    pub fixes: Option<Vec<Fix<T>>>,
    pub base_region: CodeRegion<T>,
    pub taint_flow_regions: Option<Vec<CodeRegion<T>>>,
    /// (See documentation on [`Instance`]).
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
        let base_region = position::Region::from(self.base_region);
        let taint_flow = self.taint_flow_regions.map(|flow| {
            flow.into_iter()
                .map(position::Region::from)
                .collect::<Vec<_>>()
        });

        violation::Violation {
            start: base_region.start,
            end: base_region.end,
            message: self.message,
            severity,
            category,
            fixes,
            taint_flow,
        }
    }
}

pub(crate) struct ViolationConverter {
    fix_converter: FixConverter,
    cr_converter: CodeRegionConverter,
}

impl ViolationConverter {
    pub fn new() -> Self {
        let fix_converter = FixConverter::new();
        let cr_converter = CodeRegionConverter::new();
        Self {
            fix_converter,
            cr_converter,
        }
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
        let base_region = get_field::<v8::Object>(v8_obj, "baseRegion", scope, "object")?;
        let base_region = self
            .cr_converter
            .try_convert_from(scope, v8::Local::from(base_region))?;
        let taint_flow_regions = get_optional_field::<v8::Array>(
            v8_obj,
            "taintFlowRegions",
            scope,
            "array | undefined",
        )?;
        let taint_flow_regions = taint_flow_regions
            .map(|array| {
                iter_v8_array(array, scope)
                    .map(|value| self.cr_converter.try_convert_from(scope, value))
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?;

        Ok(Violation {
            message,
            fixes,
            base_region,
            taint_flow_regions,
            _pd: PhantomData,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::analysis::ddsa_lib::common::Instance;
    use crate::analysis::ddsa_lib::js::{CodeRegion, Violation, ViolationConverter};
    use crate::analysis::ddsa_lib::test_utils::{
        cfg_test_runtime, js_class_eq, js_instance_eq, try_execute,
    };
    use crate::analysis::ddsa_lib::v8_ds::V8Converter;
    use std::marker::PhantomData;

    #[test]
    fn js_properties_canary() {
        let instance_exp = &[
            // Variables
            "fixes",
            "message",
            "baseRegion",
            "taintFlowRegions",
            // Methods
            "addFix",
        ];
        assert!(js_instance_eq(Violation::CLASS_NAME, instance_exp));
        let class_expected = &["new"];
        assert!(js_class_eq(Violation::CLASS_NAME, class_expected));
    }

    #[test]
    fn variadic_violation_creation() {
        let converter = ViolationConverter::new();
        let mut rt = cfg_test_runtime();
        let scope = &mut rt.handle_scope();

        let region0 = CodeRegion::<Instance> {
            start_line: 22,
            start_col: 1,
            end_line: 22,
            end_col: 30,
            _pd: PhantomData,
        };
        let region1 = CodeRegion::<Instance> {
            start_line: 5,
            start_col: 1,
            end_line: 5,
            end_col: 30,
            _pd: PhantomData,
        };
        let with_single_region = Violation {
            message: "abc".to_string(),
            fixes: None,
            base_region: region0,
            taint_flow_regions: None,
            _pd: PhantomData,
        };

        let single_variants = &[
            // language=javascript
            r#"
Violation.new("abc", 22, 1, 22, 30);
"#,
            // language=javascript
            r#"
Violation.new("abc", { line: 22, col: 1 }, { line: 22, col: 30 });
"#,
            // language=javascript
            r#"
const tsNode = new TreeSitterNode(0, 22, 1, 22, 30, 0);

Violation.new("abc", tsNode);
"#,
        ];
        for &code in single_variants {
            let v8_value = try_execute(scope, code).unwrap();
            let deserialized = converter.try_convert_from(scope, v8_value).unwrap();
            assert_eq!(deserialized, with_single_region);
        }

        let with_taint_flow = Violation {
            message: "abc".to_string(),
            fixes: None,
            base_region: region0,
            taint_flow_regions: Some(vec![region0, region1]),
            _pd: PhantomData,
        };
        let flow_variants = &[r#"
const tsNode0 = new TreeSitterNode(0, 22, 1, 22, 30, 0);
const tsNode1 = new TreeSitterNode(1, 5, 1, 5, 30, 0);
// Stub: initialize as empty and then re-assign
const flow = new TaintFlow([], false);
flow[0] = tsNode0;
flow[1] = tsNode1;

Violation.new("abc", flow);
"#];
        for &code in flow_variants {
            let v8_value = try_execute(scope, code).unwrap();
            let deserialized = converter.try_convert_from(scope, v8_value).unwrap();
            assert_eq!(deserialized, with_taint_flow);
        }
    }
}
