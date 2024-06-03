// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::analysis::ddsa_lib::common::v8_string;
use crate::analysis::ddsa_lib::v8_ds::MirroredIndexMap;
use deno_core::v8;
use deno_core::v8::HandleScope;

/// A stateful struct containing metadata related to a rule.
#[derive(Debug)]
pub struct RuleContext {
    /// A mapping from argument names to values
    arguments: MirroredIndexMap<String, String>,
}

impl RuleContext {
    pub fn new(scope: &mut HandleScope) -> Self {
        let arguments = MirroredIndexMap::<String, String>::new(scope);
        RuleContext { arguments }
    }

    /// Inserts an argument name and value pair
    pub fn insert_argument(
        &mut self,
        scope: &mut HandleScope,
        name: impl Into<String>,
        value: impl Into<String>,
    ) {
        let name = name.into();
        let value = value.into();
        self.arguments
            .insert_with(scope, name, value, |scope, key, value| {
                let key = v8_string(scope, key);
                let value = v8_string(scope, value);
                (key.into(), value.into())
            });
    }

    /// Clears all arguments from the map, preserving the original allocation across Rust and v8.
    pub fn clear_arguments(&mut self, scope: &mut HandleScope) {
        self.arguments.clear(scope);
    }

    /// Returns a reference to the [`v8::Global`] arguments map
    pub fn arguments_map(&self) -> &v8::Global<v8::Map> {
        self.arguments.v8_map()
    }
}
