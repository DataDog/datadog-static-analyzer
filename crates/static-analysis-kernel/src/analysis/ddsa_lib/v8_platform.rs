// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::analysis::ddsa_lib::common::DDSAJsRuntimeError;
use crate::analysis::ddsa_lib::extension::ddsa_lib;
use crate::analysis::ddsa_lib::runtime::make_base_deno_core_runtime;
use crate::analysis::ddsa_lib::JsRuntime;
use deno_core::v8;

/// A ZWT used to indicate that a [`V8Platform`] has not been initialized.
#[derive(Debug, Copy, Clone)]
pub struct Uninitialized;
/// A ZWT used to indicate that a [`V8Platform`] has been initialized.
#[derive(Debug, Copy, Clone)]
pub struct Initialized;

/// An instance of the v8 platform.
#[derive(Debug, Copy, Clone)]
pub struct V8Platform<T>(pub(crate) std::marker::PhantomData<T>);

impl V8Platform<Uninitialized> {
    /// Creates a new uninitialized [`V8Platform`].
    fn new() -> Self {
        V8Platform::<Uninitialized>(std::marker::PhantomData)
    }

    /// Creates a v8 platform with the provided `thread_pool_size` and initializes it.
    fn initialize(self, thread_pool_size: u32) -> V8Platform<Initialized> {
        let platform = v8::new_default_platform(thread_pool_size, false);
        let shared_platform = platform.make_shared();
        deno_core::JsRuntime::init_platform(Some(shared_platform));

        V8Platform::<Initialized>(std::marker::PhantomData)
    }
}

impl V8Platform<Initialized> {
    /// Creates and returns a new [`JsRuntime`] that utilizes this v8 platform.
    pub fn try_new_runtime(&self) -> Result<JsRuntime, DDSAJsRuntimeError> {
        JsRuntime::try_new(Self::make_deno_core_runtime())
    }

    fn make_deno_core_runtime() -> deno_core::JsRuntime {
        make_base_deno_core_runtime(vec![ddsa_lib::init_ops_and_esm()])
    }

    #[cfg(test)]
    pub fn new_deno_core_rt(&self) -> deno_core::JsRuntime {
        Self::make_deno_core_runtime()
    }
}

/// Initializes the process's v8 platform with the provided thread pool size. If zero is provided,
/// a suitable number based on the number of processors currently online will be used.
///
/// Returns `Some` if v8 was successfully initialized for the first time, or `None` if v8 has already been initialized.
///
/// # Caveats
/// This should only be called from the parent thread of all child threads that will access v8.
/// (e.g. the main thread). If this is not done, on modern Linux systems running on hardware
/// supporting [Memory Protection Keys], a segfault will trigger when attempting to use v8.
///
///
/// [V8 flags]: https://chromium.googlesource.com/v8/v8/+/master/src/flags/flag-definitions.h
/// [Memory Protection Keys]: https://docs.kernel.org/core-api/protection-keys.html
pub fn initialize_v8(thread_pool_size: u32) -> Option<V8Platform<Initialized>> {
    use std::sync::atomic::{AtomicBool, Ordering};
    static V8_PLATFORM_INIT: AtomicBool = AtomicBool::new(false);

    match V8_PLATFORM_INIT.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed) {
        Err(_) => None,
        Ok(_) => {
            let uninit = V8Platform::<Uninitialized>::new();
            Some(uninit.initialize(thread_pool_size))
        }
    }
}
