use fingerprint_proxy_core::error::{FpError, FpResult};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

const LOCK_POISONED_ERROR_MESSAGE: &str = "pipeline shutdown coordinator lock poisoned";
const REJECT_NEW_IN_FLIGHT_ERROR_MESSAGE: &str =
    "pipeline is shutting down: no new in-flight requests are accepted";
const DRAIN_TIMEOUT_ERROR_MESSAGE: &str =
    "graceful shutdown timed out while waiting for in-flight requests";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PipelineShutdownState {
    pub accepting_new_requests: bool,
    pub in_flight_requests: usize,
}

#[derive(Debug, Clone)]
pub struct PipelineShutdownCoordinator {
    shared: Arc<Shared>,
}

#[derive(Debug)]
struct Shared {
    state: Mutex<State>,
    drained: Condvar,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct State {
    accepting_new_requests: bool,
    in_flight_requests: usize,
}

impl Default for PipelineShutdownCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

impl PipelineShutdownCoordinator {
    pub fn new() -> Self {
        Self {
            shared: Arc::new(Shared {
                state: Mutex::new(State {
                    accepting_new_requests: true,
                    in_flight_requests: 0,
                }),
                drained: Condvar::new(),
            }),
        }
    }

    pub fn begin_in_flight_request(&self) -> FpResult<InFlightRequestGuard> {
        let mut state = self.lock_state()?;
        if !state.accepting_new_requests {
            return Err(FpError::internal(REJECT_NEW_IN_FLIGHT_ERROR_MESSAGE));
        }
        state.in_flight_requests += 1;
        drop(state);

        Ok(InFlightRequestGuard {
            shared: Arc::clone(&self.shared),
            released: false,
        })
    }

    pub fn request_shutdown(&self) -> FpResult<PipelineShutdownState> {
        let mut state = self.lock_state()?;
        state.accepting_new_requests = false;
        Ok(PipelineShutdownState {
            accepting_new_requests: state.accepting_new_requests,
            in_flight_requests: state.in_flight_requests,
        })
    }

    pub fn state(&self) -> FpResult<PipelineShutdownState> {
        let state = self.lock_state()?;
        Ok(PipelineShutdownState {
            accepting_new_requests: state.accepting_new_requests,
            in_flight_requests: state.in_flight_requests,
        })
    }

    pub fn wait_for_in_flight_requests(&self, timeout: Duration) -> FpResult<()> {
        let deadline = Instant::now() + timeout;
        let mut state = self.lock_state()?;

        while state.in_flight_requests > 0 {
            let now = Instant::now();
            if now >= deadline {
                return Err(FpError::internal(DRAIN_TIMEOUT_ERROR_MESSAGE));
            }

            let remaining = deadline.saturating_duration_since(now);
            let waited = self.shared.drained.wait_timeout(state, remaining);
            let (next_state, timed_out) = match waited {
                Ok((guard, wait)) => (guard, wait.timed_out()),
                Err(_) => return Err(FpError::internal(LOCK_POISONED_ERROR_MESSAGE)),
            };
            state = next_state;

            if timed_out && state.in_flight_requests > 0 {
                return Err(FpError::internal(DRAIN_TIMEOUT_ERROR_MESSAGE));
            }
        }

        Ok(())
    }

    fn lock_state(&self) -> FpResult<MutexGuard<'_, State>> {
        self.shared
            .state
            .lock()
            .map_err(|_| FpError::internal(LOCK_POISONED_ERROR_MESSAGE))
    }
}

#[derive(Debug)]
pub struct InFlightRequestGuard {
    shared: Arc<Shared>,
    released: bool,
}

impl InFlightRequestGuard {
    pub fn finish(mut self) {
        self.release_once();
    }

    fn release_once(&mut self) {
        if self.released {
            return;
        }
        self.released = true;

        let lock = self.shared.state.lock();
        let mut state = match lock {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        if state.in_flight_requests > 0 {
            state.in_flight_requests -= 1;
        }
        let notify = state.in_flight_requests == 0;
        drop(state);
        if notify {
            self.shared.drained.notify_all();
        }
    }
}

impl Drop for InFlightRequestGuard {
    fn drop(&mut self) {
        self.release_once();
    }
}
