use crate::counters::SecondCounter;
use fingerprint_proxy_stats_api::time_windows::EffectiveTimeWindow;

#[derive(Debug, Default)]
pub(super) struct RequestsProcessedStats {
    requests_processed: SecondCounter,
}

impl RequestsProcessedStats {
    pub(super) fn record(&mut self, at_unix: u64) {
        self.requests_processed.record(at_unix);
    }

    pub(super) fn count_in_window(&self, window: &EffectiveTimeWindow) -> u64 {
        self.requests_processed.count_in_window(window)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_processed_is_windowed() {
        let mut stats = RequestsProcessedStats::default();
        stats.record(1);
        stats.record(2);
        stats.record(2);
        let window = EffectiveTimeWindow {
            from: 2,
            to: 2,
            window_seconds: 1,
        };
        assert_eq!(stats.count_in_window(&window), 2);
    }
}
