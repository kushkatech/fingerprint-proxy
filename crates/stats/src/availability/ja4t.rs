use crate::counters::SecondCounter;
use fingerprint_proxy_stats_api::time_windows::EffectiveTimeWindow;

#[derive(Debug, Default)]
pub(crate) struct Ja4TUnavailableStats {
    unavailable: SecondCounter,
}

impl Ja4TUnavailableStats {
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
    fn ja4t_unavailable_is_windowed() {
        let mut stats = Ja4TUnavailableStats::default();
        stats.record_unavailable(10);
        stats.record_unavailable(20);

        let window = EffectiveTimeWindow {
            from: 15,
            to: 25,
            window_seconds: 10,
        };
        assert_eq!(stats.count_in_window(&window), 1);
    }
}
