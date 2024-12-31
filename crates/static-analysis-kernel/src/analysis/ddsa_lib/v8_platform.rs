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
        deno_core::JsRuntime::init_platform(Some(shared_platform), false);

        V8Platform::<Initialized>(std::marker::PhantomData)
    }
}

impl V8Platform<Initialized> {
    /// Creates and returns a new [`JsRuntime`]. The v8 isolate's heap limit is set according to
    /// the flags used to initialize this v8 platform.
    pub fn try_new_runtime(&self) -> Result<JsRuntime, DDSAJsRuntimeError> {
        JsRuntime::try_new(make_base_deno_core_runtime(Self::extensions(), None))
    }

    /// Creates and returns a new [`JsRuntime`] with the provided v8 isolate heap size limit.
    pub fn try_new_runtime_with_heap_limit(
        &self,
        max_heap_size_bytes: usize,
    ) -> Result<JsRuntime, DDSAJsRuntimeError> {
        JsRuntime::try_new(make_base_deno_core_runtime(
            Self::extensions(),
            Some(max_heap_size_bytes),
        ))
    }

    fn extensions() -> Vec<deno_core::Extension> {
        vec![ddsa_lib::init_ops_and_esm()]
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
/// # Panics
/// Panics if this function is called more than once. This is an arbitrary restriction, intended
/// to prevent code like:
/// ```text
/// let results = some_vec.into_par_iter(|item| {
///     let mut rt = initialize_v8(0).try_new_runtime().expect("should work");
///     analyze_with(
///         &mut rt,
///         // ...
///     )
/// });
/// ```
///
/// [V8 flags]: https://chromium.googlesource.com/v8/v8/+/master/src/flags/flag-definitions.h
/// [Memory Protection Keys]: https://docs.kernel.org/core-api/protection-keys.html
pub fn initialize_v8(thread_pool_size: u32) -> V8Platform<Initialized> {
    use std::sync::atomic::{AtomicBool, Ordering};
    static V8_PLATFORM_INIT: AtomicBool = AtomicBool::new(false);

    if V8_PLATFORM_INIT
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        panic!("initialize_v8 should only ever be called once");
    }

    let uninit = V8Platform::<Uninitialized>::new();
    uninit.initialize(thread_pool_size)
}

#[cfg(test)]
mod tests {
    use crate::analysis::ddsa_lib::v8_platform::initialize_v8;

    /// `initialize_v8` can effectively only be called once.
    #[test]
    fn initialize_v8_only_once() {
        let _v8 = initialize_v8(0);

        let result = std::panic::catch_unwind(|| {
            let _v8 = initialize_v8(0);
        });
        assert!(result.is_err());
    }
}
