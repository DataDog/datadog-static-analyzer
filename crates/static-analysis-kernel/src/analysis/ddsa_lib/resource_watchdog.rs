// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

use crate::analysis::ddsa_lib::common::DDSAJsRuntimeError;
use deno_core::v8;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// A persistent thread that can track execution on a [`v8::Isolate`] and terminate it if
/// a per-execution configurable duration has been exceeded.
#[derive(Debug)]
pub(crate) struct V8ResourceWatchdog {
    state: Arc<Mutex<WatchdogState>>,
    timeout_condvar: Arc<Condvar>,
    isolate_handle: v8::IsolateHandle,
}

impl V8ResourceWatchdog {
    // Creates a new watchdog that can terminate execution on a v8 isolate that exceeds a resource quota.
    pub fn new(isolate_handle: v8::IsolateHandle) -> Self {
        let state = WatchdogState::default();
        let state = Arc::new(Mutex::new(state));
        let timeout_condvar = Arc::new(Condvar::new());

        // Spawn the timeout thread, _ignoring_ the returned JoinHandle. It's ok if the thread
        // terminates itself after this `V8ResourceWatchdog` struct is dropped.
        let _ = Self::spawn_timeout_thread(
            isolate_handle.clone(),
            Arc::clone(&state),
            Arc::clone(&timeout_condvar),
        );

        Self {
            state,
            timeout_condvar,
            isolate_handle,
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

        let did_timeout = matches!(
            termination_err,
            Some(DDSAJsRuntimeError::JavaScriptTimeout { .. })
        );

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

#[cfg(test)]
mod tests {
    use super::V8ResourceWatchdog;
    use crate::analysis::ddsa_lib::common::{compile_script, DDSAJsRuntimeError};
    use crate::analysis::ddsa_lib::test_utils::cfg_test_v8;
    use deno_core::v8;
    use std::time::{Duration, Instant};

    /// The watchdog's state should be properly cleared across executions.
    #[test]
    fn watchdog_state_cleared() {
        let mut runtime = cfg_test_v8().deno_core_rt();
        let timeout = Duration::from_millis(500);
        let loop_code = "while (true) {}";
        let loop_script = compile_script(&mut runtime.handle_scope(), loop_code).unwrap();
        let code = "123;";
        let normal_script = compile_script(&mut runtime.handle_scope(), code).unwrap();

        let watchdog = V8ResourceWatchdog::new(runtime.v8_isolate().thread_safe_handle());

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
}
