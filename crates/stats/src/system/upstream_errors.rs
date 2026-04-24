use crate::counters::SecondCounter;
use fingerprint_proxy_stats_api::time_windows::EffectiveTimeWindow;

#[derive(Debug, Default)]
pub(super) struct UpstreamErrorStats {
    upstream_errors: SecondCounter,
}

impl UpstreamErrorStats {
    pub(super) fn record(&mut self, at_unix: u64) {
        self.upstream_errors.record(at_unix);
    }

    pub(super) fn count_in_window(&self, window: &EffectiveTimeWindow) -> u64 {
        self.upstream_errors.count_in_window(window)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_errors_is_windowed() {
        let mut stats = UpstreamErrorStats::default();
        stats.record(50);
        stats.record(60);
        let window = EffectiveTimeWindow {
            from: 55,
            to: 65,
            window_seconds: 10,
        };
        assert_eq!(stats.count_in_window(&window), 1);
    }
}
