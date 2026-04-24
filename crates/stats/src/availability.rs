mod ja4t;
mod tls;

use crate::availability::ja4t::Ja4TUnavailableStats;
use crate::availability::tls::TlsDataUnavailableStats;
use crate::counters::SecondCounter;
use fingerprint_proxy_core::fingerprint::{
    Fingerprint, FingerprintAvailability, FingerprintFailureReason, FingerprintKind,
};
use fingerprint_proxy_stats_api::time_windows::EffectiveTimeWindow;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct DataAvailabilitySnapshot {
    pub(crate) ja4t_unavailable: u64,
    pub(crate) tls_data_unavailable: u64,
    pub(crate) protocol_data_unavailable: u64,
}

#[derive(Debug, Default)]
pub(crate) struct DataAvailabilityStats {
    ja4t: Ja4TUnavailableStats,
    tls: TlsDataUnavailableStats,
    protocol_data_unavailable: SecondCounter,
}

impl DataAvailabilityStats {
    pub(crate) fn record_ja4t_unavailable(&mut self, at_unix: u64) {
        self.ja4t.record_unavailable(at_unix);
    }

    pub(crate) fn record_tls_data_unavailable(&mut self, at_unix: u64) {
        self.tls.record_unavailable(at_unix);
    }

    pub(crate) fn record_protocol_data_unavailable(&mut self, at_unix: u64) {
        self.protocol_data_unavailable.record(at_unix);
    }

    pub(crate) fn record_from_fingerprint(&mut self, at_unix: u64, fingerprint: &Fingerprint) {
        if fingerprint.availability == FingerprintAvailability::Complete {
            return;
        }

        if fingerprint.failure_reason != Some(FingerprintFailureReason::MissingRequiredData) {
            return;
        }

        match fingerprint.kind {
            FingerprintKind::Ja4T => self.record_ja4t_unavailable(at_unix),
            FingerprintKind::Ja4 => self.record_tls_data_unavailable(at_unix),
            FingerprintKind::Ja4One => self.record_protocol_data_unavailable(at_unix),
        }
    }

    pub(crate) fn snapshot(&self, window: &EffectiveTimeWindow) -> DataAvailabilitySnapshot {
        DataAvailabilitySnapshot {
            ja4t_unavailable: self.ja4t.count_in_window(window),
            tls_data_unavailable: self.tls.count_in_window(window),
            protocol_data_unavailable: self.protocol_data_unavailable.count_in_window(window),
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
    fn records_explicit_availability_kinds() {
        let mut stats = DataAvailabilityStats::default();
        stats.record_ja4t_unavailable(120);
        stats.record_tls_data_unavailable(121);
        stats.record_protocol_data_unavailable(122);

        let snapshot = stats.snapshot(&window());
        assert_eq!(snapshot.ja4t_unavailable, 1);
        assert_eq!(snapshot.tls_data_unavailable, 1);
        assert_eq!(snapshot.protocol_data_unavailable, 1);
    }

    #[test]
    fn record_from_fingerprint_tracks_only_missing_required_data() {
        let mut stats = DataAvailabilityStats::default();
        stats.record_from_fingerprint(
            130,
            &Fingerprint {
                kind: FingerprintKind::Ja4T,
                availability: FingerprintAvailability::Unavailable,
                value: None,
                computed_at: None,
                failure_reason: Some(FingerprintFailureReason::MissingRequiredData),
            },
        );
        stats.record_from_fingerprint(
            131,
            &Fingerprint {
                kind: FingerprintKind::Ja4,
                availability: FingerprintAvailability::Partial,
                value: None,
                computed_at: None,
                failure_reason: Some(FingerprintFailureReason::MissingRequiredData),
            },
        );
        stats.record_from_fingerprint(
            132,
            &Fingerprint {
                kind: FingerprintKind::Ja4One,
                availability: FingerprintAvailability::Unavailable,
                value: None,
                computed_at: None,
                failure_reason: Some(FingerprintFailureReason::ParsingError),
            },
        );

        let snapshot = stats.snapshot(&window());
        assert_eq!(snapshot.ja4t_unavailable, 1);
        assert_eq!(snapshot.tls_data_unavailable, 1);
        assert_eq!(snapshot.protocol_data_unavailable, 0);
    }
}
