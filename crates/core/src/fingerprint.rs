use std::time::SystemTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FingerprintKind {
    Ja4T,
    Ja4,
    Ja4One,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FingerprintAvailability {
    Complete,
    Partial,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FingerprintFailureReason {
    MissingRequiredData,
    ParsingError,
    ComputationError,
    Timeout,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fingerprint {
    pub kind: FingerprintKind,
    pub availability: FingerprintAvailability,
    pub value: Option<String>,
    pub computed_at: Option<SystemTime>,
    pub failure_reason: Option<FingerprintFailureReason>,
}

impl Fingerprint {
    pub fn unavailable(kind: FingerprintKind) -> Self {
        Self {
            kind,
            availability: FingerprintAvailability::Unavailable,
            value: None,
            computed_at: None,
            failure_reason: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fingerprints {
    pub ja4t: Fingerprint,
    pub ja4: Fingerprint,
    pub ja4one: Fingerprint,
}

impl Default for Fingerprints {
    fn default() -> Self {
        Self {
            ja4t: Fingerprint::unavailable(FingerprintKind::Ja4T),
            ja4: Fingerprint::unavailable(FingerprintKind::Ja4),
            ja4one: Fingerprint::unavailable(FingerprintKind::Ja4One),
        }
    }
}
