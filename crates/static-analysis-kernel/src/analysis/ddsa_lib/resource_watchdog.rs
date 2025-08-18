// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

use crate::analysis::ddsa_lib::common::DDSAJsRuntimeError;
use deno_core::v8;
use std::cell::Cell;
use std::rc::Rc;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// A persistent thread that can track execution on a [`v8::Isolate`] and terminate it if
/// a per-execution configurable duration has been exceeded.
#[derive(Debug)]
pub(crate) struct V8ResourceWatchdog {
    state: Arc<Mutex<WatchdogState>>,
    timeout_condvar: Arc<Condvar>,
    isolate_handle: v8::IsolateHandle,
    heap_limit_guard: Rc<HeapLimitGuard>,
    /// The heap limit to enforce for the v8 isolate.
    initial_heap_limit: usize,
}

impl V8ResourceWatchdog {
    // Creates a new watchdog that can terminate execution on a v8 isolate that exceeds a resource quota.
    pub fn new(isolate: &mut v8::Isolate) -> Self {
        let state = WatchdogState::default();
        let state = Arc::new(Mutex::new(state));
        let timeout_condvar = Arc::new(Condvar::new());
        let isolate_handle = isolate.thread_safe_handle();

        // Spawn the timeout thread, _ignoring_ the returned JoinHandle. It's ok if the thread
        // terminates itself after this `V8ResourceWatchdog` struct is dropped.
        let _ = Self::spawn_timeout_thread(
            isolate_handle.clone(),
            Arc::clone(&state),
            Arc::clone(&timeout_condvar),
        );

        let mut stats = v8::HeapStatistics::default();
        isolate.get_heap_statistics(&mut stats);
        let initial_heap_limit = stats.heap_size_limit();

        let heap_limit_cb =
            Self::make_near_heap_limit_callback(isolate_handle.clone(), Arc::clone(&state));
        let heap_limit_guard = HeapLimitGuard::new(isolate, Box::new(heap_limit_cb));

        Self {
            state,
            timeout_condvar,
            isolate_handle,
            heap_limit_guard,
            initial_heap_limit,
        }
    }

    /// Executes the provided closure, optionally enforcing a resource constraint:
    /// * A `timeout_duration` can be specified to limit the time of a single execution of a [`v8::Isolate`].
    pub fn execute<'rt, 's, F, T, S>(
        &'rt self,
        timeout_duration: Option<Duration>,
        scope: &mut S,
        f: F,
    ) -> Result<T, DDSAJsRuntimeError>
    where
        'rt: 's,
        F: Fn(&mut S) -> T,
        S: AsMut<v8::Isolate>,
    {
        // Request to cancel any in-progress terminations. If there is not one
        // (i.e. `v8::IsolateHandle::is_execution_terminating()` is false), this is a no-op.
        self.isolate_handle.cancel_terminate_execution();

        let mut using_timeout = false;
        if let Some(duration) = timeout_duration {
            using_timeout = true;
            let mut state = self.state.lock().unwrap();
            let _ = state.timeout.timings.insert((Instant::now(), duration));
            drop(state);
            self.timeout_condvar.notify_one();
        }

        let execution_result = f(scope);

        let mut state = self.state.lock().unwrap();
        let termination_err = state.termination_err.take();
        state.timeout.timings = None;
        drop(state);

        let (did_timeout, did_oom) = match termination_err {
            Some(DDSAJsRuntimeError::JavaScriptTimeout { .. }) => (true, false),
            Some(DDSAJsRuntimeError::JavaScriptMemoryExceeded) => (false, true),
            _ => (false, false),
        };

        // If the isolate was terminated via a `NearHeapLimitCallback`, it was given
        // an additional memory allotment that needs to be reset to the initial value.
        if did_oom {
            self.heap_limit_guard
                .suggest_heap_limit(scope.as_mut(), self.initial_heap_limit)
                .expect("init params should guarantee success");
        }

        // (If the watchdog timed out an execution, a wakeup isn't necessary because it's already
        // at the "beginning" state and waiting for the next execution to start)
        if using_timeout && !did_timeout {
            self.timeout_condvar.notify_one();
        }

        match termination_err {
            None => Ok(execution_result),
            Some(e) => Err(e),
        }
    }

    /// Spawns a thread that calls [`terminate_execution`](v8::Isolate::terminate_execution) on a
    /// JavaScript execution that exceeds a time quota. This thread can be communicated with via
    /// the shared [`WatchdogState`] and woken up with the provided condvar.
    fn spawn_timeout_thread(
        isolate_handle: v8::IsolateHandle,
        wd_state: Arc<Mutex<WatchdogState>>,
        condvar: Arc<Condvar>,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let (lock, cvar) = (wd_state, condvar);
            loop {
                let mut state = cvar
                    .wait_while(lock.lock().unwrap(), |state| {
                        state.timeout.timings.is_none() && !state.timeout.thread_should_shut_down
                    })
                    .expect("mutex should not be poisoned");

                if state.timeout.thread_should_shut_down {
                    break;
                }

                match state.termination_err {
                    Some(DDSAJsRuntimeError::JavaScriptTimeout { .. }) => {
                        unreachable!("handler should have taken value")
                    }
                    // Race condition: a different watchdog called `terminate_execution`, but before v8 could
                    // do that, this watchdog's condition triggered. In this case, we let the first one handle termination.
                    Some(_) => continue,
                    None => {}
                }

                let (start_instant, timeout_duration) =
                    state.timeout.timings.expect("should meet cvar condition");

                // Any instant after `timeout_threshold` will trigger the timeout
                let timeout_threshold = start_instant + timeout_duration;
                let now = Instant::now();

                if now >= timeout_threshold {
                    // This branch represents an edge case where the OS couldn't wake this thread up
                    // until after the watchdog should've already triggered a timeout.
                    state.timeout.timings = None;
                    state.termination_err = Some(DDSAJsRuntimeError::JavaScriptTimeout {
                        timeout: timeout_duration,
                    });
                    drop(state);
                    isolate_handle.terminate_execution();
                } else {
                    // This is guaranteed not to underflow
                    let additional_wait = timeout_threshold - now;
                    let result = cvar
                        .wait_timeout_while(state, additional_wait, |state| {
                            state.timeout.timings.is_some()
                        })
                        .expect("mutex should not be poisoned");
                    state = result.0;

                    // If the condvar triggered a timeout, because of our use of `Condvar::wait_timeout_while`,
                    // there _must_ be an actively tracked timeout, Thus, it's always appropriate to terminate execution.
                    if result.1.timed_out() {
                        state.timeout.timings = None;
                        state.termination_err = Some(DDSAJsRuntimeError::JavaScriptTimeout {
                            timeout: timeout_duration,
                        });
                        drop(state);
                        isolate_handle.terminate_execution();
                    }
                }
            }
        })
    }

    /// Builds a [`NearHeapLimitCallback`] to enforce a memory quota for v8 executions.
    /// This callback signals the execution to terminate and increases the heap limit to prevent
    /// v8 from crashing before it can fully terminate the execution.
    fn make_near_heap_limit_callback(
        isolate_handle: v8::IsolateHandle,
        wd_state: Arc<Mutex<WatchdogState>>,
    ) -> Box<NearHeapLimitCallback> {
        let cb = move |current_heap_limit: usize, _initial_heap_limit: usize| {
            let mut state = wd_state.lock().unwrap();
            match state.termination_err {
                Some(DDSAJsRuntimeError::JavaScriptMemoryExceeded) => {
                    unreachable!("handler should have taken value")
                }
                // Race condition: a different watchdog called `terminate_execution`, but before v8 could
                // do that, this watchdog's condition triggered. In this case, we let the first
                // one handle termination, and so we don't allot any additional memory. (v8 performs
                // a no-op if the returned value is lower than the current limit).
                Some(_) => return 0,
                None => {}
            }

            let _ = state
                .termination_err
                .replace(DDSAJsRuntimeError::JavaScriptMemoryExceeded);
            drop(state);
            isolate_handle.terminate_execution();

            // Increase the heap limit by 50% to provide a generous leeway to avoid v8 from
            // crashing with `V8::FatalProcessOutOfMemory`.
            //
            // Note: there is still technically a race where the currently-executing JavaScript
            // can allocate more than this additional leeway before the v8 isolate can process
            // the terminate_execution call, in which case the process will crash (we reduce
            // the likelihood of this by giving a large leeway).
            current_heap_limit + (current_heap_limit / 2)
        };
        Box::new(cb)
    }
}

impl Drop for V8ResourceWatchdog {
    fn drop(&mut self) {
        let mut state = self.state.lock().unwrap();
        state.timeout.thread_should_shut_down = true;
        drop(state);
        // Wake the spawned thread so that it can terminate itself.
        self.timeout_condvar.notify_one();
    }
}

/// State for a [`V8ResourceWatchdog`] that needs to be synchronized in a thread-safe manner.
#[derive(Default, Debug)]
struct WatchdogState {
    timeout: TimeoutState,
    /// This will be `Some` if there was a termination. Otherwise, it will be `None`.
    termination_err: Option<DDSAJsRuntimeError>,
}

/// State for the timeout watchdog implemented by a [`V8ResourceWatchdog`]. This should be guarded
/// with a mutex.
#[derive(Default, Debug, Clone, Eq, PartialEq, Hash)]
struct TimeoutState {
    /// Data for an active timeout watchdog. If no execution is being tracked, this will be `None`.
    /// If an execution is being tracked, this will be `Some((start_instant, timeout_duration))`.
    timings: Option<(Instant, Duration)>,
    thread_should_shut_down: bool,
}

/// A callback that is invoked when a v8 isolate is nearing a heap limit.
///
/// The function parameters are `(current_heap_limit: usize, initial_heap_limit: usize)`,
/// where `current_heap_limit` is the limit before invocation, and `initial_heap_limit`
/// is the limit the isolate was initialized with.
///
/// The return value will set a new heap limit only if it is greater than `current_heap_limit`.
type NearHeapLimitCallback = dyn Fn(usize, usize) -> usize;

/// This struct provides the ability to set the heap limit on a v8 isolate as well as gracefully
/// recover from executions that allocate past that limit.
///
/// When a v8 isolate allocates enough to nearly reach its heap limit, it forces garbage collection,
/// and if that doesn't free enough memory, it will invoke a caller-provided callback function.
/// This function can terminate execution on the isolate, or increase the limit. This callback
/// needs to be registered with v8 by providing the isolate a raw pointer to the function.
///
/// This struct registers [`Self::ffi_near_heap_limit_callback`] as this callback, which has a `'static` lifetime,
/// and is thus guaranteed to outlive the v8 isolate. However, the callback itself attempts
/// to dereference a pointer that must point to a live [`NearHeapLimitCallback`] (which, by default,
/// will not live as long as the v8 isolate). Thus, this struct guarantees memory safety
/// by manually managing the allocation and lifetime of the `NearHeapLimitCallback`.
#[derive(Debug, Clone)]
struct HeapLimitGuard {
    boxed_callback_ptr: Cell<*mut Box<NearHeapLimitCallback>>,
    /// The raw pointer of the isolate this guard was initialized with. This is only used to assert
    /// that, for each function that accepts a `&mut v8::Isolate`, that the provided isolate is
    /// the same as the one that initialized this `HeapLimitGuard`.
    parent_isolate_ptr: *const v8::Isolate,
    /// The limit of the v8 isolate upon initialization.
    initial_limit: usize,
}

impl HeapLimitGuard {
    /// Creates a new reference-counted `HeapLimitGuard` which is guaranteed to live as long
    /// as the provided `isolate`.
    fn new(isolate: &mut v8::Isolate, near_heap_limit_cb: Box<NearHeapLimitCallback>) -> Rc<Self> {
        // We need to pass a thin pointer to v8 so we can safely dereference it into a Rust
        // function that can be called. `NearHeapLimitCallback` is a trait object (and thus a fat
        // pointer), and so we need to wrap the boxed callback `near_heap_limit_cb` (hereafter: "Child Box")
        // with an additional box (hereafter: "Parent Box"). We then leak the "Parent Box"
        // in order to get a `*mut Box<NearHeapLimitCallback>` , which is a thin pointer to the "Child Box".
        // that is guaranteed to never be dropped.
        let boxed_box = Box::new(near_heap_limit_cb);
        let boxed_callback_ptr = Box::into_raw(boxed_box);
        let isolate_ptr: *const v8::Isolate = &*isolate;
        let mut stats = v8::HeapStatistics::default();
        isolate.get_heap_statistics(&mut stats);
        let initial_limit = stats.heap_size_limit();

        let guard = Self {
            boxed_callback_ptr: Cell::new(boxed_callback_ptr),
            parent_isolate_ptr: isolate_ptr,
            initial_limit,
        };
        let guard = Rc::new(guard);
        // Giving the v8 isolate an owned `Rc` of this `HeapLimitGuard` ensures that the callbacks
        // allocated within this struct will live as long as the isolate.
        let was_new = isolate.set_slot(Rc::clone(&guard));
        assert!(was_new, "isolate should not have other HeapLimitGuard");

        // As described in the documentation at the start of this function, the data we pass to v8
        // is the pointer to the provided `Box<NearHeapLimitCallback>`.
        let data = guard.boxed_callback_ptr.get() as *mut std::ffi::c_void;
        isolate.add_near_heap_limit_callback(Self::ffi_near_heap_limit_callback, data);

        guard
    }

    /// Instructs v8 to set a new heap limit, returning `Ok` if successful.
    ///
    /// # Caveats
    /// The limit after invoking this function will be *approximately* the provided limit.
    /// V8 includes an additional buffer on top of the provided value that depends on many
    /// dynamic factors that cannot be reasonably predicted.
    ///
    /// See [source code] for `Heap::RestoreHeapLimit` for the exact calculation logic.
    ///
    /// [source code]: https://chromium.googlesource.com/v8/v8.git/+/refs/heads/main/src/heap/heap.h
    fn suggest_heap_limit(
        &self,
        isolate: &mut v8::Isolate,
        heap_size_limit: usize,
    ) -> Result<(), &'static str> {
        if !std::ptr::eq(&*isolate as *const _, self.parent_isolate_ptr) {
            return Err("isolate must be the same as the one that initialized this guard");
        }
        if heap_size_limit > self.initial_limit {
            return Err("limit can not be set higher than the initial value");
        }

        let current_ptr = self.boxed_callback_ptr.get();

        // v8 uses the size of currently-allocated objects as part of its calculation. If we don't
        // trigger a garbage collection, allocations that can be GC'd will inflate the value v8
        // ends up using.
        isolate.low_memory_notification();

        // v8 doesn't expose a way to alter the heap limit directly, but it does through
        // the `Heap::RemoveNearHeapLimitCallback` method. Thus, we have to go through the
        // slightly-janky flow of removing our callback and then immediately re-adding it back
        // so we can indirectly trigger the `Heap::RestoreHeapLimit` method.
        //
        // See: https://chromium.googlesource.com/v8/v8.git/+/refs/heads/main/src/heap/heap.cc
        let _ = self.set_callback_inner(isolate, current_ptr, heap_size_limit);
        Ok(())
    }

    /// Sets the [`NearHeapLimitCallback`] used by the v8 isolate, replacing and returning a
    /// previously-registered callback, if it exists.
    ///
    /// `heap_limit` behaves as documented on [`remove_near_heap_limit_callback`](v8::Isolate::remove_near_heap_limit_callback).
    fn set_callback_inner(
        &self,
        isolate: &mut v8::Isolate,
        boxed_callback_ptr: *mut Box<NearHeapLimitCallback>,
        heap_limit: usize,
    ) -> Option<Box<NearHeapLimitCallback>> {
        let mut old_callback: Option<Box<NearHeapLimitCallback>> = None;

        // Unregister the callback from the isolate.
        isolate.remove_near_heap_limit_callback(Self::ffi_near_heap_limit_callback, heap_limit);

        let current_ptr_ref = self.boxed_callback_ptr.get();
        // If the incoming callback pointer is not the same as the current one, we need to box
        // and return the old one to avoid leaking memory.
        if !std::ptr::eq(current_ptr_ref, boxed_callback_ptr) {
            // Safety: `self.boxed_callback_ptr` is only populated with a raw pointer converted from a Box
            // with `Box::into_raw`. v8 does not mutate the underlying pointer or data. Thus, it's
            // always safe to dereference this pointer and (re)construct the Box.
            let boxed_old_cb = unsafe { Box::from_raw(current_ptr_ref) };
            let old_cb = *boxed_old_cb;
            let _ = old_callback.insert(old_cb);

            self.boxed_callback_ptr.set(boxed_callback_ptr);
        }

        let data = current_ptr_ref as *mut std::ffi::c_void;
        isolate.add_near_heap_limit_callback(Self::ffi_near_heap_limit_callback, data);

        old_callback
    }

    /// A [`v8::NearHeapLimitCallback`] that is called via FFI by v8.
    ///
    /// This function assumes that the passed in `data` is a pointer to a valid `NearHeapLimitCallback`,
    /// which will be dereferenced and executed, returning the result back to v8.
    extern "C" fn ffi_near_heap_limit_callback(
        data: *mut std::ffi::c_void,
        current_heap_limit: usize,
        initial_heap_limit: usize,
    ) -> usize {
        // Re-construct the "Parent Box" (see `HeapLimitGuard::new` for documentation).
        // Note that this is a zero-cost abstraction to safely reference the below pointer as a boxed callback.
        //
        // Safety:
        // * The value of `data` will be whatever we pass to v8. We always pass in the value contained
        //   by the `boxed_callback_ptr` Cell in `HeapLimitGuard::set_callback_inner`. This value is
        //   always a pointer to a live, boxed `NearHeapLimitCallback`.
        // * A `HeapLimitGuard` can never exist without it being wrapped by an `Rc`. A clone of that
        //   `Rc` is always given to the `v8::Isolate`. Thus, it's guaranteed that the function
        //   referenced by `data` is live, and thus can safely be dereferenced.
        let boxed_callback = unsafe { Box::from_raw(data as *mut Box<NearHeapLimitCallback>) };
        let cb_value = boxed_callback(current_heap_limit, initial_heap_limit);

        // `boxed_callback` was used as a zero-cost abstraction to handle the dereferencing
        // of the `*mut Box<NearHeapLimitCallback>`. Thus, to avoid triggering this box's
        // Drop impl, we need to re-convert it back to its raw form.
        // We can then ignore the returned pointer in this function because `HeapLimitGuard::set_callback_inner`
        // is responsible for manually managing its lifetime.
        let _ = Box::into_raw(boxed_callback);
        cb_value
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::{HeapLimitGuard, NearHeapLimitCallback, V8ResourceWatchdog};
    use crate::analysis::ddsa_lib::common::{compile_script, DDSAJsRuntimeError};
    use crate::analysis::ddsa_lib::test_utils::cfg_test_v8;
    use deno_core::v8;
    use std::rc::Rc;
    use std::time::{Duration, Instant};

    /// JavaScript code that will trigger an out-of-memory error in v8.
    pub(crate) const OOM_CODE: &str =
        // language=javascript
        "\
(() => {
    let str = '';
    for (let i = 0; i < Number.MAX_SAFE_INTEGER; i++) {
        str = str + `abc${i}-`;
    }
    return str.length;
})();
";

    /// 128MB: a heap limit large enough to test expected v8 behavior while still respecting a
    /// low resource utilization for the test runner.
    pub(crate) const DEFAULT_HEAP_LIMIT: usize = 128 * 1024 * 1024;
    /// A 5% margin of error, used to confirm that calls to [`HeapLimitGuard::suggest_heap_limit`] have
    /// the desired effect. Note that this is a relatively large % because it's paired with [`DEFAULT_HEAP_LIMIT`],
    /// which is relatively small. (As the limit grows to a value more realistic
    /// for production use -- e.g. 1+ GB -- the actual margin of error drops below 1%)
    const HEAP_LIMIT_MARGIN_OF_ERROR: f32 = 0.05;

    /// Returns the percentage difference between the isolate's current heap limit
    /// and the expected heap limit.
    fn heap_limit_diff(isolate: &mut v8::Isolate, expected: usize) -> f32 {
        let mut stats = v8::HeapStatistics::default();
        isolate.get_heap_statistics(&mut stats);
        let current_limit = stats.heap_size_limit() as isize;
        let diff = current_limit.abs_diff(expected as isize);
        diff as f32 / expected as f32
    }

    /// The watchdog's state should be properly cleared across executions.
    /// Note that because this is testing the [`V8ResourceWatchdog::execute`] function, which we
    /// expect to have the state-clearing logic, we only need to trigger _some_ kind of termination.
    /// (i.e. an out-of-memory termination functions identically, so there is no need to test it).
    #[test]
    fn watchdog_execute_state_cleared() {
        let mut runtime = cfg_test_v8().deno_core_rt();
        let timeout = Duration::from_millis(500);
        let loop_code = "while (true) {}";
        let loop_script = compile_script(&mut runtime.handle_scope(), loop_code, None).unwrap();
        let code = "123;";
        let normal_script = compile_script(&mut runtime.handle_scope(), code, None).unwrap();

        let watchdog = V8ResourceWatchdog::new(runtime.v8_isolate());

        // First, ensure that the implementation isn't forcing a minimum execution time to that of the
        // timeout (which could happen if we are improperly handling a mutex lock).
        let now = Instant::now();
        let scope = &mut runtime.handle_scope();
        let tc_scope = &mut v8::TryCatch::new(scope);

        let res = watchdog.execute(Some(Duration::from_secs(10)), tc_scope, |sc| {
            let opened = normal_script.open(sc);
            let bound_script = opened.bind_to_current_context(sc);
            bound_script.run(sc)
        });
        assert!(res.is_ok());
        assert!(now.elapsed() < Duration::from_secs(10));

        let transitions = [
            (Some(timeout), Some(timeout + Duration::from_millis(1))),
            (None, Some(timeout)),
            // After calling `TerminateExecution`, a v8 isolate cannot execute JavaScript until all frames have
            // propagated the uncatchable exception (or we've manually cancelled the termination). Invoking
            // a subsequent non-timing-out script execution ensures that we're handling this properly.
            (Some(timeout), None),
            (None, None),
        ];
        // Ensure that the state for each execution is as expected, even after a previous execution
        // with a potentially different timeout setting.
        for (first, second) in transitions {
            for timeout_duration in [first, second] {
                assert!(watchdog.state.lock().unwrap().termination_err.is_none());
                assert!(watchdog.state.lock().unwrap().timeout.timings.is_none());
                let res = watchdog.execute(timeout_duration, &mut *tc_scope, |sc| {
                    // The timer should have been configured with the correct timeout.
                    if let Some((_, stored_duration)) =
                        watchdog.state.lock().unwrap().timeout.timings
                    {
                        assert_eq!(stored_duration, timeout_duration.unwrap())
                    } else {
                        // If `timings` is none, the test case should be `None` as well.
                        assert!(timeout_duration.is_none());
                    }
                    // Run the infinite loop if a timeout is configured, otherwise a normal script.
                    let opened = if timeout_duration.is_some() {
                        loop_script.open(sc)
                    } else {
                        normal_script.open(sc)
                    };
                    let bound_script = opened.bind_to_current_context(sc);
                    bound_script.run(sc)
                });
                // There should be a timeout error if we configured one, otherwise not.
                if timeout_duration.is_some() {
                    assert!(matches!(
                        res.unwrap_err(),
                        DDSAJsRuntimeError::JavaScriptTimeout { .. }
                    ));
                } else {
                    assert!(res.is_ok());
                }
                assert!(watchdog.state.lock().unwrap().termination_err.is_none());
                assert!(watchdog.state.lock().unwrap().timeout.timings.is_none());
            }
        }
    }

    /// The [`V8ResourceWatchdog`] should terminate an execution that over-allocates.
    /// Because this involves bumping the v8 heap limit, the `execute` function should properly
    /// reset the heap limit.
    #[test]
    fn watchdog_oom_termination() {
        const INITIAL_LIMIT: usize = DEFAULT_HEAP_LIMIT;
        let mut runtime = cfg_test_v8().deno_core_rt_with_heap_limit(INITIAL_LIMIT);
        let watchdog = V8ResourceWatchdog::new(runtime.v8_isolate());

        let scope = &mut runtime.handle_scope();
        let tc_scope = &mut v8::TryCatch::new(scope);
        let oom_script = compile_script(tc_scope, OOM_CODE, None).unwrap();

        let mut last_margin: Option<f32> = None;
        // A loop is performed to ensure the original limit is reset and that the margin of
        // error doesn't snowball beyond the acceptable margin.
        for i in 0..3 {
            let err = watchdog
                .execute(None, tc_scope, |sc| {
                    let opened = oom_script.open(sc);
                    let bound_script = opened.bind_to_current_context(sc);
                    // Run a script that will try to allocate effectively infinite memory
                    bound_script.run(sc);
                })
                .unwrap_err();
            assert!(matches!(err, DDSAJsRuntimeError::JavaScriptMemoryExceeded));
            let margin = heap_limit_diff(tc_scope, INITIAL_LIMIT);
            assert!(margin < HEAP_LIMIT_MARGIN_OF_ERROR, "[{i}] margin exceeded");

            // Ensure there is no drift in the margin (prevent snowballing).
            if let Some(last_margin) = last_margin.replace(margin) {
                assert_eq!(last_margin, margin, "[{i}] margin drifted");
            }
        }
    }

    /// Ensures that the heap limit guard returned by [`HeapLimitGuard::new`] lives as long as the v8 isolate.
    #[test]
    fn heap_limit_guard_lifetime() {
        let mut runtime = cfg_test_v8().deno_core_rt();
        let boxed_cb: Box<NearHeapLimitCallback> = Box::new(|_, _| 0);

        let guard = HeapLimitGuard::new(runtime.v8_isolate(), boxed_cb);
        let stored_guard = runtime.v8_isolate().get_slot::<Rc<HeapLimitGuard>>();
        assert!(stored_guard.is_some_and(|stored_guard| Rc::ptr_eq(&guard, stored_guard)));
    }

    /// Ensures that the [`HeapLimitGuard`] properly handles the full lifecycle of a boxed `NearHeapLimitCallback`
    /// callback without leaking memory.
    #[test]
    fn heap_limit_guard_set_callback_inner() {
        let mut runtime = cfg_test_v8().deno_core_rt();
        let boxed_cb1: Box<NearHeapLimitCallback> =
            Box::new(|current, initial| current * 2 + initial);
        assert_eq!(boxed_cb1(5, 1), 11);

        let mut boxed_cb2: Box<NearHeapLimitCallback> =
            Box::new(|current, initial| current * 5 + initial);
        assert_eq!(boxed_cb2(5, 1), 26);
        let raw_cb2_ptr = std::ptr::from_mut(&mut boxed_cb2);

        // Note: given that `NearHeapLimitCallback` is a trait object, it's more straightforward to compare
        // and assert equality by dereferencing and calling the closures rather than inspecting memory addresses.
        // Thus, the test requires that the two callbacks must return different values given the same input:
        assert_ne!(boxed_cb1(5, 1), boxed_cb2(5, 1), "test invariant");

        let guard = HeapLimitGuard::new(runtime.v8_isolate(), boxed_cb1);

        // The stored pointer should be able to be dereferenced to the expected callback.
        let stored_ptr = guard.boxed_callback_ptr.get();
        assert_eq!(unsafe { (*stored_ptr)(5, 1) }, 11);

        // The old callback is returned when setting a new callback.
        let old_cb = guard.set_callback_inner(runtime.v8_isolate(), raw_cb2_ptr, 0);
        assert!(old_cb.is_some_and(|cb| cb(5, 1) == 11));

        // The stored pointer should be able to be dereferenced to the new callback.
        let stored_ptr = guard.boxed_callback_ptr.get();
        assert_eq!(unsafe { (*stored_ptr)(5, 1) }, 26);
    }

    /// A [`HeapLimitGuard`] can set the heap limit of an isolate (within a margin of error).
    #[test]
    fn heap_limit_guard_set_heap_limit_margin_of_error() {
        const INITIAL_LIMIT: usize = DEFAULT_HEAP_LIMIT;
        const REDUCED_LIMIT: usize = INITIAL_LIMIT / 2;
        const _: () = {
            assert!(REDUCED_LIMIT < INITIAL_LIMIT, "test invariant");
        };
        let mut runtime = cfg_test_v8().deno_core_rt_with_heap_limit(INITIAL_LIMIT);
        assert_eq!(heap_limit_diff(runtime.v8_isolate(), INITIAL_LIMIT), 0.0);

        let guard = HeapLimitGuard::new(runtime.v8_isolate(), Box::new(|_, _| 0));

        let set_result = guard.suggest_heap_limit(runtime.v8_isolate(), REDUCED_LIMIT);
        assert!(set_result.is_ok());
        // The `suggest_heap_limit` call should have set a lower limit.
        assert!(heap_limit_diff(runtime.v8_isolate(), REDUCED_LIMIT) < HEAP_LIMIT_MARGIN_OF_ERROR);
    }

    /// The heap limit cannot be set larger than the initial value.
    #[test]
    fn heap_limit_initial_value() {
        const INITIAL_LIMIT: usize = DEFAULT_HEAP_LIMIT;
        let mut runtime = cfg_test_v8().deno_core_rt_with_heap_limit(INITIAL_LIMIT);
        let guard = HeapLimitGuard::new(runtime.v8_isolate(), Box::new(|_, _| 0));

        assert_eq!(heap_limit_diff(runtime.v8_isolate(), INITIAL_LIMIT), 0.0);

        // Setting a limit larger than the initial value isn't possible.
        let set_result = guard.suggest_heap_limit(runtime.v8_isolate(), INITIAL_LIMIT * 2);
        assert!(set_result
            .is_err_and(|msg| msg == "limit can not be set higher than the initial value"));

        assert_eq!(heap_limit_diff(runtime.v8_isolate(), INITIAL_LIMIT), 0.0);
    }

    /// A `HeapLimitGuard` only works on the isolate it was initialized with.
    #[test]
    fn heap_limit_guard_correct_isolate() {
        const INITIAL_LIMIT: usize = DEFAULT_HEAP_LIMIT;
        const REDUCED_LIMIT: usize = INITIAL_LIMIT / 2;
        let v8_platform = cfg_test_v8();
        let mut runtime_1 = v8_platform.deno_core_rt_with_heap_limit(INITIAL_LIMIT);
        let guard_for_rt_1 = HeapLimitGuard::new(runtime_1.v8_isolate(), Box::new(|_, _| 0));
        let mut runtime_2 = v8_platform.deno_core_rt_with_heap_limit(INITIAL_LIMIT);
        let suggest_result =
            guard_for_rt_1.suggest_heap_limit(runtime_2.v8_isolate(), REDUCED_LIMIT);
        assert!(suggest_result.is_err_and(
            |msg| msg == "isolate must be the same as the one that initialized this guard"
        ));
        assert!(guard_for_rt_1
            .suggest_heap_limit(runtime_1.v8_isolate(), REDUCED_LIMIT)
            .is_ok());
    }
}
