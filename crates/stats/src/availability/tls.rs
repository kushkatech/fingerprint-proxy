use crate::counters::SecondCounter;
use fingerprint_proxy_stats_api::time_windows::EffectiveTimeWindow;

#[derive(Debug, Default)]
pub(crate) struct TlsDataUnavailableStats {
    unavailable: SecondCounter,
}

impl TlsDataUnavailableStats {
    pub(crate) fn record_unavailable(&mut self, at_unix: u64) {
        self.unavailable.record(at_unix);
    }

    pub(crate) fn count_in_window(&self, window: &EffectiveTimeWindow) -> u64 {
        self.unavailable.count_in_window(window)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_data_unavailable_is_windowed() {
        let mut stats = TlsDataUnavailableStats::default();
        stats.record_unavailable(100);
        stats.record_unavailable(101);
        stats.record_unavailable(200);

        let window = EffectiveTimeWindow {
            from: 100,
            to: 150,
            window_seconds: 50,
        };
        assert_eq!(stats.count_in_window(&window), 2);
    }
}
