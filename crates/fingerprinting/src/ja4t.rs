pub mod availability;
pub mod complete;
pub mod partial;
pub mod unavailable;

use crate::availability::FingerprintAvailability;
use crate::model::{FingerprintComputationMetadata, FingerprintComputationResult};
use fingerprint_proxy_core::fingerprint::{
    Fingerprint, FingerprintFailureReason, FingerprintKind, Fingerprints,
};
pub use fingerprint_proxy_core::fingerprinting::Ja4TInput;
use std::time::SystemTime;

pub fn compute_ja4t_only(
    input: Option<&Ja4TInput>,
    computed_at: SystemTime,
) -> FingerprintComputationResult {
    let ja4t = compute_ja4t_fingerprint(input, computed_at);
    FingerprintComputationResult {
        fingerprints: Fingerprints {
            ja4t,
            ja4: Fingerprint::unavailable(FingerprintKind::Ja4),
            ja4one: Fingerprint::unavailable(FingerprintKind::Ja4One),
        },
        metadata: FingerprintComputationMetadata {
            computed_at,
            ja4one_components: None,
        },
    }
}

pub fn compute_ja4t_fingerprint(input: Option<&Ja4TInput>, computed_at: SystemTime) -> Fingerprint {
    let Some(input) = input else {
        return unavailable::unavailable_missing_data(computed_at);
    };

    if input.window_size.is_none() {
        return unavailable::unavailable_missing_data(computed_at);
    }

    let availability = availability::availability(input);
    let value = match availability {
        FingerprintAvailability::Complete => Some(complete::format_complete(input)),
        FingerprintAvailability::Partial => Some(partial::format_partial(input)),
        FingerprintAvailability::Unavailable => None,
    };

    Fingerprint {
        kind: FingerprintKind::Ja4T,
        availability,
        value,
        computed_at: Some(computed_at),
        failure_reason: match availability {
            FingerprintAvailability::Unavailable => {
                Some(FingerprintFailureReason::MissingRequiredData)
            }
            _ => None,
        },
    }
}
