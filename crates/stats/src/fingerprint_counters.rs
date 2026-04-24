use crate::counters::SecondCounter;
use fingerprint_proxy_core::fingerprint::FingerprintAvailability;
use fingerprint_proxy_stats_api::aggregation::FingerprintCounters;
use fingerprint_proxy_stats_api::time_windows::EffectiveTimeWindow;

#[derive(Debug, Default)]
pub(crate) struct FingerprintCountersState {
    attempts: SecondCounter,
    successes: SecondCounter,
    partials: SecondCounter,
    failures: SecondCounter,
}

impl FingerprintCountersState {
    pub(crate) fn record(&mut self, at_unix: u64, availability: FingerprintAvailability) {
        self.attempts.record(at_unix);
        match availability {
            FingerprintAvailability::Complete => self.successes.record(at_unix),
            FingerprintAvailability::Partial => self.partials.record(at_unix),
            FingerprintAvailability::Unavailable => self.failures.record(at_unix),
        }
    }

    pub(crate) fn snapshot(&self, window: &EffectiveTimeWindow) -> FingerprintCounters {
        FingerprintCounters {
            attempts: self.attempts.count_in_window(window),
            successes: self.successes.count_in_window(window),
            partials: self.partials.count_in_window(window),
            failures: self.failures.count_in_window(window),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn window() -> EffectiveTimeWindow {
        EffectiveTimeWindow {
            from: 100,
            to: 200,
            window_seconds: 100,
        }
    }

    #[test]
    fn records_attempts_and_outcomes_per_availability() {
        let mut counters = FingerprintCountersState::default();
        counters.record(120, FingerprintAvailability::Complete);
        counters.record(121, FingerprintAvailability::Partial);
        counters.record(122, FingerprintAvailability::Unavailable);

        let snapshot = counters.snapshot(&window());
        assert_eq!(snapshot.attempts, 3);
        assert_eq!(snapshot.successes, 1);
        assert_eq!(snapshot.partials, 1);
        assert_eq!(snapshot.failures, 1);
    }
}
