use crate::counters::SecondCounter;
use fingerprint_proxy_stats_api::time_windows::EffectiveTimeWindow;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(super) struct ConfigurationUpdateSnapshot {
    pub(super) successful_updates: u64,
    pub(super) failed_updates: u64,
}

#[derive(Debug, Default)]
pub(super) struct ConfigurationUpdateStats {
    successful_updates: SecondCounter,
    failed_updates: SecondCounter,
}

impl ConfigurationUpdateStats {
    pub(super) fn record_success(&mut self, at_unix: u64) {
        self.successful_updates.record(at_unix);
    }

    pub(super) fn record_failure(&mut self, at_unix: u64) {
        self.failed_updates.record(at_unix);
    }

    pub(super) fn snapshot(&self, window: &EffectiveTimeWindow) -> ConfigurationUpdateSnapshot {
        ConfigurationUpdateSnapshot {
            successful_updates: self.successful_updates.count_in_window(window),
            failed_updates: self.failed_updates.count_in_window(window),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_update_stats_are_windowed() {
        let mut stats = ConfigurationUpdateStats::default();
        stats.record_success(10);
        stats.record_success(20);
        stats.record_failure(20);
        stats.record_failure(30);
        let window = EffectiveTimeWindow {
            from: 15,
            to: 25,
            window_seconds: 10,
        };
        let snapshot = stats.snapshot(&window);
        assert_eq!(snapshot.successful_updates, 1);
        assert_eq!(snapshot.failed_updates, 1);
    }
}
