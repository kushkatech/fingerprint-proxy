use crate::counters::SecondCounter;
use fingerprint_proxy_stats_api::time_windows::EffectiveTimeWindow;

#[derive(Debug, Default)]
pub(super) struct TotalConnectionsStats {
    total_connections: SecondCounter,
}

impl TotalConnectionsStats {
    pub(super) fn record_opened(&mut self, at_unix: u64) {
        self.total_connections.record(at_unix);
    }

    pub(super) fn count_in_window(&self, window: &EffectiveTimeWindow) -> u64 {
        self.total_connections.count_in_window(window)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn total_connections_is_windowed() {
        let mut stats = TotalConnectionsStats::default();
        stats.record_opened(100);
        stats.record_opened(120);

        let window = EffectiveTimeWindow {
            from: 110,
            to: 130,
            window_seconds: 20,
        };
        assert_eq!(stats.count_in_window(&window), 1);
    }
}
