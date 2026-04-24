use crate::counters::SecondCounter;
use fingerprint_proxy_stats_api::time_windows::EffectiveTimeWindow;

#[derive(Debug, Default)]
pub(super) struct ComputationFailureCounter {
    inner: SecondCounter,
}

impl ComputationFailureCounter {
    pub(super) fn record(&mut self, at_unix: u64) {
        self.inner.record(at_unix);
    }

    pub(super) fn count_in_window(&self, window: &EffectiveTimeWindow) -> u64 {
        self.inner.count_in_window(window)
    }
}
