use crate::counters::SecondCounter;
use fingerprint_proxy_core::fingerprint::{
    Fingerprint, FingerprintAvailability, FingerprintFailureReason,
};
use fingerprint_proxy_stats_api::aggregation::{FailureCategories, FingerprintCounters};
use fingerprint_proxy_stats_api::time_windows::EffectiveTimeWindow;

#[derive(Debug, Default)]
pub(crate) struct Ja4TAvailabilityStats {
    attempts: SecondCounter,
    complete: SecondCounter,
    partial: SecondCounter,
    unavailable: SecondCounter,
    missing_data: SecondCounter,
    parsing_errors: SecondCounter,
    computation_errors: SecondCounter,
    timeouts: SecondCounter,
}

impl Ja4TAvailabilityStats {
    pub(crate) fn record(&mut self, at_unix: u64, fingerprint: &Fingerprint) {
        self.attempts.record(at_unix);

        match fingerprint.availability {
            FingerprintAvailability::Complete => {
                self.complete.record(at_unix);
            }
            FingerprintAvailability::Partial => {
                self.partial.record(at_unix);
                self.record_failure_reason(at_unix, fingerprint.failure_reason);
            }
            FingerprintAvailability::Unavailable => {
                self.unavailable.record(at_unix);
                self.record_failure_reason(at_unix, fingerprint.failure_reason);
            }
        }
    }

    fn record_failure_reason(&mut self, at_unix: u64, reason: Option<FingerprintFailureReason>) {
        match reason {
            Some(FingerprintFailureReason::MissingRequiredData) => {
                self.missing_data.record(at_unix);
            }
            Some(FingerprintFailureReason::ParsingError) => {
                self.parsing_errors.record(at_unix);
            }
            Some(FingerprintFailureReason::ComputationError)
            | Some(FingerprintFailureReason::Other) => {
                self.computation_errors.record(at_unix);
            }
            Some(FingerprintFailureReason::Timeout) => {
                self.timeouts.record(at_unix);
            }
            None => {}
        }
    }

    pub(crate) fn snapshot(
        &self,
        window: &EffectiveTimeWindow,
    ) -> (FingerprintCounters, FailureCategories) {
        (
            FingerprintCounters {
                attempts: self.attempts.count_in_window(window),
                successes: self.complete.count_in_window(window),
                partials: self.partial.count_in_window(window),
                failures: self.unavailable.count_in_window(window),
            },
            FailureCategories {
                missing_data: self.missing_data.count_in_window(window),
                parsing_errors: self.parsing_errors.count_in_window(window),
                computation_errors: self.computation_errors.count_in_window(window),
                timeouts: self.timeouts.count_in_window(window),
            },
        )
    }
}
