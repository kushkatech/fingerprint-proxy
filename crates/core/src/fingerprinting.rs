use crate::fingerprint::{FingerprintAvailability, FingerprintFailureReason, Fingerprints};
use std::net::IpAddr;
use std::time::SystemTime;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FingerprintHeaderConfig {
    pub ja4t_header: String,
    pub ja4_header: String,
    pub ja4one_header: String,
}

impl Default for FingerprintHeaderConfig {
    fn default() -> Self {
        Self {
            ja4t_header: "X-JA4T".to_string(),
            ja4_header: "X-JA4".to_string(),
            ja4one_header: "X-JA4One".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FingerprintHeaderValue {
    pub value: Option<String>,
    pub availability: FingerprintAvailability,
    pub failure_reason: Option<FingerprintFailureReason>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FingerprintHeaderPlan {
    pub ja4t: (String, FingerprintHeaderValue),
    pub ja4: (String, FingerprintHeaderValue),
    pub ja4one: (String, FingerprintHeaderValue),
}

pub fn plan_fingerprint_headers(
    config: &FingerprintHeaderConfig,
    fingerprints: &Fingerprints,
) -> FingerprintHeaderPlan {
    FingerprintHeaderPlan {
        ja4t: (
            config.ja4t_header.clone(),
            FingerprintHeaderValue {
                value: fingerprints.ja4t.value.clone(),
                availability: fingerprints.ja4t.availability,
                failure_reason: fingerprints.ja4t.failure_reason,
            },
        ),
        ja4: (
            config.ja4_header.clone(),
            FingerprintHeaderValue {
                value: fingerprints.ja4.value.clone(),
                availability: fingerprints.ja4.availability,
                failure_reason: fingerprints.ja4.failure_reason,
            },
        ),
        ja4one: (
            config.ja4one_header.clone(),
            FingerprintHeaderValue {
                value: fingerprints.ja4one.value.clone(),
                availability: fingerprints.ja4one.availability,
                failure_reason: fingerprints.ja4one.failure_reason,
            },
        ),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ja4TInput {
    pub window_size: Option<u16>,
    pub option_kinds_in_order: Vec<u8>,
    pub mss: Option<u16>,
    pub window_scale: Option<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ja4Input {
    pub tls_version: Option<u16>,
    pub supported_versions: Option<Vec<u16>>,
    pub cipher_suites: Option<Vec<u16>>,
    pub extensions: Option<Vec<u16>>,
    pub alpn: Option<Vec<String>>,
    pub signature_algorithms: Option<Vec<u16>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ja4OneInput {
    pub tls_version: Option<u16>,
    pub actual_tls_version: Option<u16>,
    pub supported_versions: Option<Vec<u16>>,
    pub cipher_suites: Vec<u16>,
    pub extensions: Vec<u16>,
    pub alpn: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FingerprintComputationInputs {
    pub ja4t: Option<Ja4TInput>,
    pub ja4: Option<Ja4Input>,
    pub ja4one: Option<Ja4OneInput>,
}

impl FingerprintComputationInputs {
    pub fn is_empty(&self) -> bool {
        self.ja4t.is_none() && self.ja4.is_none() && self.ja4one.is_none()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportHint {
    Tcp,
    Quic,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionTuple {
    pub source_ip: IpAddr,
    pub source_port: u16,
    pub destination_ip: IpAddr,
    pub destination_port: u16,
    pub transport: TransportHint,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FingerprintComputationRequest {
    pub connection: ConnectionTuple,
    pub inputs: FingerprintComputationInputs,
    pub tls_client_hello: Option<Vec<u8>>,
    pub tcp_metadata: Option<Vec<u8>>,
    pub protocol_metadata: Option<Vec<u8>>,
    pub received_at: SystemTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FingerprintComputationMetadata {
    pub computed_at: SystemTime,
    pub ja4one_components: Option<Ja4OneComponentContext>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FingerprintComputationResult {
    pub fingerprints: Fingerprints,
    pub metadata: FingerprintComputationMetadata,
}

impl FingerprintComputationResult {
    pub fn from_parts(
        ja4t: crate::fingerprint::Fingerprint,
        ja4: crate::fingerprint::Fingerprint,
        ja4one: crate::fingerprint::Fingerprint,
        computed_at: SystemTime,
    ) -> Self {
        Self {
            fingerprints: Fingerprints { ja4t, ja4, ja4one },
            metadata: FingerprintComputationMetadata {
                computed_at,
                ja4one_components: None,
            },
        }
    }

    pub fn from_parts_with_ja4one_components(
        ja4t: crate::fingerprint::Fingerprint,
        ja4: crate::fingerprint::Fingerprint,
        ja4one: crate::fingerprint::Fingerprint,
        computed_at: SystemTime,
        ja4one_components: Option<Ja4OneComponentContext>,
    ) -> Self {
        Self {
            fingerprints: Fingerprints { ja4t, ja4, ja4one },
            metadata: FingerprintComputationMetadata {
                computed_at,
                ja4one_components,
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ja4OneComponentName {
    Ja4OneInput,
    Ja4T,
    Ja4,
    Protocol,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ja4OneComponentAvailabilitySummary {
    pub ja4one_input: FingerprintAvailability,
    pub ja4t: FingerprintAvailability,
    pub ja4: FingerprintAvailability,
    pub protocol: FingerprintAvailability,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Ja4OneComponentContributionSummary {
    pub contributing: Vec<Ja4OneComponentName>,
    pub partial: Vec<Ja4OneComponentName>,
    pub unavailable: Vec<Ja4OneComponentName>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ja4OneComponentContext {
    pub availability: Ja4OneComponentAvailabilitySummary,
    pub contributions: Ja4OneComponentContributionSummary,
}
