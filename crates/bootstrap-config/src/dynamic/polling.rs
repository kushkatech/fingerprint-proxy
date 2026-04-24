use fingerprint_proxy_core::error::{FpError, FpResult};
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PollingConfig {
    interval: Duration,
}

impl PollingConfig {
    pub fn new(interval: Duration) -> FpResult<Self> {
        if interval.is_zero() {
            return Err(FpError::invalid_configuration(
                "dynamic polling interval must be greater than zero",
            ));
        }
        Ok(Self { interval })
    }

    pub fn interval(self) -> Duration {
        self.interval
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PollDecision {
    pub should_poll_now: bool,
    pub wait_for: Duration,
}

pub fn polling_decision(
    config: PollingConfig,
    elapsed_since_last_poll: Option<Duration>,
) -> PollDecision {
    match elapsed_since_last_poll {
        None => PollDecision {
            should_poll_now: true,
            wait_for: Duration::ZERO,
        },
        Some(elapsed) if elapsed >= config.interval() => PollDecision {
            should_poll_now: true,
            wait_for: Duration::ZERO,
        },
        Some(elapsed) => PollDecision {
            should_poll_now: false,
            wait_for: config.interval() - elapsed,
        },
    }
}
