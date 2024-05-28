// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::analysis::ddsa_lib::common::DDSAJsRuntimeError;
use crate::analysis::ddsa_lib::extension::ddsa_lib;
use std::cell::{RefCell, RefMut};
use std::rc::Rc;

/// The Datadog Static Analyzer JavaScript runtime
pub struct JsRuntime {
    runtime: deno_core::JsRuntime,
    console: Rc<RefCell<JsConsole>>,
}

impl JsRuntime {
    pub fn try_new() -> Result<Self, DDSAJsRuntimeError> {
        let mut runtime = base_js_runtime();
        let console = Rc::new(RefCell::new(JsConsole::new()));
        runtime.op_state().borrow_mut().put(Rc::clone(&console));

        Ok(Self { runtime, console })
    }

    /// Provides a mutable reference to the underlying [`deno_core::JsRuntime`].
    ///
    /// NOTE: This is temporary scaffolding used during the transition to `ddsa_lib::JsRuntime`.
    pub fn inner_compat(&mut self) -> &mut deno_core::JsRuntime {
        &mut self.runtime
    }

    /// Provides a mutable reference to the `console` implementation.
    ///
    /// NOTE: This is temporary scaffolding used during the transition to `ddsa_lib::JsRuntime`.
    ///
    /// # Panics
    /// Panics if the `RefCell` can't be borrowed mutably.
    pub fn console_compat(&mut self) -> RefMut<'_, JsConsole> {
        self.console.borrow_mut()
    }
}

/// Constructs a [`deno_core::JsRuntime`] with the [`ddsa_lib`] extension enabled.
pub(crate) fn base_js_runtime() -> deno_core::JsRuntime {
    deno_core::JsRuntime::new(deno_core::RuntimeOptions {
        extensions: vec![ddsa_lib::init_ops_and_esm()],
        ..Default::default()
    })
}

/// A mutable scratch space that collects the output of the `console.log` function invoked by JavaScript code.
pub(crate) struct JsConsole(Vec<String>);

impl JsConsole {
    /// Creates a new, empty `Console`.
    pub fn new() -> Self {
        Self(Vec::new())
    }

    /// Appends a string to the console.
    pub fn push(&mut self, value: impl Into<String>) {
        self.0.push(value.into())
    }

    /// Removes all lines from the `Console`, returning them as an iterator.
    pub fn drain(&mut self) -> impl Iterator<Item = String> + '_ {
        self.0.drain(..)
    }
}
