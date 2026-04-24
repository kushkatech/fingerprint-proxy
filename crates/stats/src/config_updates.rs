use crate::counters::SecondCounter;
use fingerprint_proxy_stats_api::time_windows::EffectiveTimeWindow;

#[derive(Debug, Default)]
pub(crate) struct ConfigUpdateWindowStats {
    successful_updates: SecondCounter,
    failed_updates: SecondCounter,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct ConfigUpdateCounters {
    pub(crate) successful_updates: u64,
    pub(crate) failed_updates: u64,
}

impl ConfigUpdateWindowStats {
    pub(crate) fn record_success(&mut self, at_unix: u64) {
        self.successful_updates.record(at_unix);
    }

    pub(crate) fn record_failure(&mut self, at_unix: u64) {
        self.failed_updates.record(at_unix);
    }

    pub(crate) fn snapshot(&self, window: &EffectiveTimeWindow) -> ConfigUpdateCounters {
        ConfigUpdateCounters {
            successful_updates: self.successful_updates.count_in_window(window),
            failed_updates: self.failed_updates.count_in_window(window),
        }
    }
}
