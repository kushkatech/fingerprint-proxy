mod computation;
mod missing_data;
mod parsing;
mod timeouts;

use crate::failures::computation::ComputationFailureCounter;
use crate::failures::missing_data::MissingDataFailureCounter;
use crate::failures::parsing::ParsingFailureCounter;
use crate::failures::timeouts::TimeoutFailureCounter;
use fingerprint_proxy_core::fingerprint::FingerprintFailureReason;
use fingerprint_proxy_stats_api::aggregation::FailureCategories;
use fingerprint_proxy_stats_api::time_windows::EffectiveTimeWindow;

#[derive(Debug, Default)]
pub(crate) struct FailureCategoryStats {
    missing_data: MissingDataFailureCounter,
    parsing_errors: ParsingFailureCounter,
    computation_errors: ComputationFailureCounter,
    timeouts: TimeoutFailureCounter,
}

impl FailureCategoryStats {
    pub(crate) fn record_reason(&mut self, at_unix: u64, reason: Option<FingerprintFailureReason>) {
        match reason {
            Some(FingerprintFailureReason::MissingRequiredData) => {
                self.missing_data.record(at_unix)
            }
            Some(FingerprintFailureReason::ParsingError) => self.parsing_errors.record(at_unix),
            Some(FingerprintFailureReason::ComputationError)
            | Some(FingerprintFailureReason::Other) => self.computation_errors.record(at_unix),
            Some(FingerprintFailureReason::Timeout) => self.timeouts.record(at_unix),
            None => {}
        }
    }

    pub(crate) fn snapshot(&self, window: &EffectiveTimeWindow) -> FailureCategories {
        FailureCategories {
            missing_data: self.missing_data.count_in_window(window),
            parsing_errors: self.parsing_errors.count_in_window(window),
            computation_errors: self.computation_errors.count_in_window(window),
            timeouts: self.timeouts.count_in_window(window),
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
    fn records_failure_reason_categories_deterministically() {
        let mut stats = FailureCategoryStats::default();
        stats.record_reason(120, Some(FingerprintFailureReason::MissingRequiredData));
        stats.record_reason(121, Some(FingerprintFailureReason::ParsingError));
        stats.record_reason(122, Some(FingerprintFailureReason::ComputationError));
        stats.record_reason(123, Some(FingerprintFailureReason::Timeout));
        stats.record_reason(124, Some(FingerprintFailureReason::Other));
        stats.record_reason(125, None);

        let snapshot = stats.snapshot(&window());
        assert_eq!(snapshot.missing_data, 1);
        assert_eq!(snapshot.parsing_errors, 1);
        assert_eq!(snapshot.computation_errors, 2);
        assert_eq!(snapshot.timeouts, 1);
    }
}
