use crate::availability::{DataAvailabilitySnapshot, DataAvailabilityStats};
use crate::failures::FailureCategoryStats;
use crate::fingerprint_counters::FingerprintCountersState;
use fingerprint_proxy_core::fingerprint::{Fingerprint, FingerprintAvailability};
use fingerprint_proxy_stats_api::aggregation::{FailureCategories, FingerprintCounters};
use fingerprint_proxy_stats_api::time_windows::EffectiveTimeWindow;

#[derive(Debug, Default)]
pub(crate) struct FingerprintTypeStats {
    counters: FingerprintCountersState,
    failures: FailureCategoryStats,
    availability: DataAvailabilityStats,
}

impl FingerprintTypeStats {
    pub(crate) fn record(&mut self, at_unix: u64, fingerprint: &Fingerprint) {
        self.counters.record(at_unix, fingerprint.availability);

        if fingerprint.availability != FingerprintAvailability::Complete {
            self.failures
                .record_reason(at_unix, fingerprint.failure_reason);
        }

        self.availability
            .record_from_fingerprint(at_unix, fingerprint);
    }

    pub(crate) fn snapshot(
        &self,
        window: &EffectiveTimeWindow,
    ) -> (FingerprintCounters, FailureCategories) {
        (
            self.counters.snapshot(window),
            self.failures.snapshot(window),
        )
    }

    pub(crate) fn availability_snapshot(
        &self,
        window: &EffectiveTimeWindow,
    ) -> DataAvailabilitySnapshot {
        self.availability.snapshot(window)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fingerprint_proxy_core::fingerprint::{FingerprintFailureReason, FingerprintKind};

    fn window() -> EffectiveTimeWindow {
        EffectiveTimeWindow {
            from: 100,
            to: 200,
            window_seconds: 100,
        }
    }

    #[test]
    fn records_fingerprint_counters_failures_and_availability() {
        let mut stats = FingerprintTypeStats::default();
        stats.record(
            120,
            &Fingerprint {
                kind: FingerprintKind::Ja4,
                availability: FingerprintAvailability::Complete,
                value: Some("ja4".to_string()),
                computed_at: None,
                failure_reason: None,
            },
        );
        stats.record(
            121,
            &Fingerprint {
                kind: FingerprintKind::Ja4,
                availability: FingerprintAvailability::Partial,
                value: Some("partial".to_string()),
                computed_at: None,
                failure_reason: Some(FingerprintFailureReason::Timeout),
            },
        );
        stats.record(
            122,
            &Fingerprint {
                kind: FingerprintKind::Ja4,
                availability: FingerprintAvailability::Unavailable,
                value: None,
                computed_at: None,
                failure_reason: Some(FingerprintFailureReason::MissingRequiredData),
            },
        );

        let (counters, failures) = stats.snapshot(&window());
        assert_eq!(counters.attempts, 3);
        assert_eq!(counters.successes, 1);
        assert_eq!(counters.partials, 1);
        assert_eq!(counters.failures, 1);
        assert_eq!(failures.timeouts, 1);
        assert_eq!(failures.missing_data, 1);

        let availability = stats.availability_snapshot(&window());
        assert_eq!(availability.tls_data_unavailable, 1);
    }
}
