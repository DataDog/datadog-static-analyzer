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
/// A ZWT used to indicate that a [`V8Platform`] has manually set v8 flags.
#[derive(Debug, Copy, Clone)]
pub struct FlagsSet;
/// A ZWT used to indicate that a [`V8Platform`] has been initialized.
#[derive(Debug, Copy, Clone)]
pub struct Initialized;
/// A ZWT used to indicate that a [`V8Platform`] has been initialized with an unprotected platform.
#[derive(Debug, Copy, Clone)]
pub(crate) struct Unprotected;

// A list of flags that will always be set upon initializing v8.
const BASE_FLAGS: &str = concat!(
    // [17.01.25] We cannot prevent `deno_core` from calling `v8::V8::set_flags_from_string`,
    // and so it's possible for changes in their default flags to contradict ours. Until `deno_core`
    // allows the creation of a JsRuntime without forcing v8 flags, we use the following flag
    // to crash the process if there is a contradiction. This serves as a canary to investigate further.
    " --abort-on-contradictory-flags",
    // Performance: compile JavaScript eagerly
    " --no-lazy",
    " --no-lazy-streaming",
    // Don't allow "eval"-like functionality.
    " --disallow-code-generation-from-strings",
    // Require each context to explicitly provide a SharedArrayBuffer implementation.
    " --enable-sharedarraybuffer-per-context",
);

/// An instance of the v8 platform.
#[derive(Debug, Copy, Clone)]
pub struct V8Platform<T>(pub(crate) std::marker::PhantomData<T>);

impl V8Platform<Uninitialized> {
    /// Creates a new uninitialized [`V8Platform`].
    pub(crate) fn new() -> Self {
        V8Platform::<Uninitialized>(std::marker::PhantomData)
    }

    /// Sets the flags provided to v8, using [`BASE_FLAGS`].
    pub(crate) fn set_flags(self) -> V8Platform<FlagsSet> {
        v8::V8::set_flags_from_string(BASE_FLAGS);
        V8Platform::<FlagsSet>(std::marker::PhantomData)
    }
}

impl V8Platform<FlagsSet> {
    /// Creates a v8 platform with the provided `thread_pool_size` and initializes it.
    fn initialize(self, thread_pool_size: u32) -> V8Platform<Initialized> {
        let platform = v8::new_default_platform(thread_pool_size, false);
        Self::initialize_inner::<Initialized>(platform)
    }

    /// Creates an unprotected v8 platform, which does not enforce thread-isolated allocations.
    /// This should only be used for tests.
    pub(crate) fn initialize_unprotected(self, thread_pool_size: u32) -> V8Platform<Unprotected> {
        let platform = v8::new_unprotected_default_platform(thread_pool_size, false);
        Self::initialize_inner::<Unprotected>(platform)
    }

    fn initialize_inner<T>(platform: v8::UniqueRef<v8::Platform>) -> V8Platform<T> {
        let shared_platform = platform.make_shared();
        deno_core::JsRuntime::init_platform(Some(shared_platform), false);
        V8Platform::<T>(std::marker::PhantomData)
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
    uninit.set_flags().initialize(thread_pool_size)
}

#[cfg(test)]
mod tests {
    use super::{initialize_v8, BASE_FLAGS};
    use crate::analysis::ddsa_lib::test_utils::{cfg_test_v8, try_execute};

    /// `initialize_v8` can effectively only be called once.
    #[test]
    fn initialize_v8_only_once() {
        let _v8 = initialize_v8(0);

        let result = std::panic::catch_unwind(|| {
            let _v8 = initialize_v8(0);
        });
        assert!(result.is_err());
    }

    /// v8 is initialized with `--abort-on-contradictory-flags`.
    /// (This is important -- see documentation in [`BASE_FLAGS`] -- hence it has an explicit test).
    #[test]
    fn v8_contradictory_flags_abort() {
        assert!(BASE_FLAGS.contains("--abort-on-contradictory-flags"));
    }

    /// v8 is initialized without the ability to run `eval`-like functions.
    #[test]
    fn v8_eval_like_disabled() {
        let v8 = cfg_test_v8();
        let mut rt = v8.new_runtime();
        let scope = &mut rt.v8_handle_scope();
        let samples = [
            "eval('1 + 2');",
            "new Function('a', 'b', 'return a + b;')(1, 2);",
        ];
        for code in samples {
            let res = try_execute(scope, code);
            assert_eq!(
                res.unwrap_err(),
                "EvalError: Code generation from strings disallowed for this context"
            );
        }
    }
}
