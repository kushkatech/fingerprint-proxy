use fingerprint_proxy_core::fingerprint::{
    Fingerprint, FingerprintAvailability, FingerprintFailureReason, FingerprintKind,
};
use std::time::SystemTime;

pub fn unavailable_missing_data(computed_at: SystemTime) -> Fingerprint {
    Fingerprint {
        kind: FingerprintKind::Ja4T,
        availability: FingerprintAvailability::Unavailable,
        value: None,
        computed_at: Some(computed_at),
        failure_reason: Some(FingerprintFailureReason::MissingRequiredData),
    }
}
