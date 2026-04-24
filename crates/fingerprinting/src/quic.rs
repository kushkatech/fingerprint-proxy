use crate::availability::{FingerprintAvailability, FingerprintFailureReason};
use crate::ja4one::{compute_ja4one_fingerprint, Ja4OneInput};
use crate::model::{FingerprintComputationMetadata, FingerprintComputationResult};
use fingerprint_proxy_core::fingerprint::{Fingerprint, FingerprintKind, Fingerprints};
use sha2::{Digest, Sha256};
use std::time::SystemTime;

const REQUIRED_QUIC_METADATA_FIELDS: [&str; 3] = [
    "version",
    "destination_connection_id_len",
    "packet_number_length",
];

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QuicFingerprintMetadata {
    pub version: Option<u32>,
    pub destination_connection_id_len: Option<usize>,
    pub source_connection_id_len: Option<usize>,
    pub packet_number_length: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicMetadataAvailabilitySummary {
    pub availability: FingerprintAvailability,
    pub missing_required_fields: Vec<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicMetadataSignature {
    pub availability: FingerprintAvailability,
    pub value: Option<String>,
    pub missing_required_fields: Vec<&'static str>,
    pub failure_reason: Option<FingerprintFailureReason>,
}

pub fn compute_quic_ja4one_only(
    input: Option<&Ja4OneInput>,
    quic_metadata: Option<&QuicFingerprintMetadata>,
    computed_at: SystemTime,
) -> FingerprintComputationResult {
    let ja4one = compute_quic_ja4one_fingerprint(input, quic_metadata, computed_at);
    FingerprintComputationResult {
        fingerprints: Fingerprints {
            ja4t: Fingerprint::unavailable(FingerprintKind::Ja4T),
            ja4: Fingerprint::unavailable(FingerprintKind::Ja4),
            ja4one,
        },
        metadata: FingerprintComputationMetadata {
            computed_at,
            ja4one_components: None,
        },
    }
}

pub fn compute_quic_ja4one_fingerprint(
    input: Option<&Ja4OneInput>,
    quic_metadata: Option<&QuicFingerprintMetadata>,
    computed_at: SystemTime,
) -> Fingerprint {
    let Some(input) = input else {
        return unavailable_missing_required_data(computed_at);
    };

    let availability_summary = summarize_quic_metadata(quic_metadata);
    if availability_summary.availability == FingerprintAvailability::Unavailable {
        return unavailable_missing_required_data(computed_at);
    }

    let base = compute_ja4one_fingerprint(Some(input), computed_at);
    let Some(base_value) = base.value.as_deref() else {
        return Fingerprint {
            kind: FingerprintKind::Ja4One,
            availability: FingerprintAvailability::Unavailable,
            value: None,
            computed_at: Some(computed_at),
            failure_reason: Some(FingerprintFailureReason::ComputationError),
        };
    };

    let Some(value) = with_quic_transport_prefix(base_value) else {
        return Fingerprint {
            kind: FingerprintKind::Ja4One,
            availability: FingerprintAvailability::Unavailable,
            value: None,
            computed_at: Some(computed_at),
            failure_reason: Some(FingerprintFailureReason::ComputationError),
        };
    };

    Fingerprint {
        kind: FingerprintKind::Ja4One,
        availability: availability_summary.availability,
        value: Some(value),
        computed_at: Some(computed_at),
        failure_reason: None,
    }
}

pub fn summarize_quic_metadata(
    quic_metadata: Option<&QuicFingerprintMetadata>,
) -> QuicMetadataAvailabilitySummary {
    let Some(metadata) = quic_metadata else {
        return QuicMetadataAvailabilitySummary {
            availability: FingerprintAvailability::Unavailable,
            missing_required_fields: REQUIRED_QUIC_METADATA_FIELDS.to_vec(),
        };
    };

    let mut missing_required_fields = Vec::new();
    if metadata.version.is_none() {
        missing_required_fields.push(REQUIRED_QUIC_METADATA_FIELDS[0]);
    }
    if metadata.destination_connection_id_len.is_none() {
        missing_required_fields.push(REQUIRED_QUIC_METADATA_FIELDS[1]);
    }
    if metadata.packet_number_length.is_none() {
        missing_required_fields.push(REQUIRED_QUIC_METADATA_FIELDS[2]);
    }

    let required_present_count =
        REQUIRED_QUIC_METADATA_FIELDS.len() - missing_required_fields.len();
    let availability = if missing_required_fields.is_empty() {
        FingerprintAvailability::Complete
    } else if required_present_count == 0 {
        FingerprintAvailability::Unavailable
    } else {
        FingerprintAvailability::Partial
    };

    QuicMetadataAvailabilitySummary {
        availability,
        missing_required_fields,
    }
}

pub fn compute_quic_metadata_signature(
    quic_metadata: Option<&QuicFingerprintMetadata>,
) -> QuicMetadataSignature {
    let summary = summarize_quic_metadata(quic_metadata);
    if summary.availability != FingerprintAvailability::Complete {
        return QuicMetadataSignature {
            availability: FingerprintAvailability::Unavailable,
            value: None,
            missing_required_fields: summary.missing_required_fields,
            failure_reason: Some(FingerprintFailureReason::MissingRequiredData),
        };
    }

    let metadata = quic_metadata.expect("quic metadata is present when summary is complete");
    let canonical = canonical_quic_metadata_input(metadata);
    QuicMetadataSignature {
        availability: FingerprintAvailability::Complete,
        value: Some(format!("qmeta1_{}", hash12(&canonical))),
        missing_required_fields: Vec::new(),
        failure_reason: None,
    }
}

fn canonical_quic_metadata_input(metadata: &QuicFingerprintMetadata) -> String {
    // Canonical order is fixed to keep deterministic signatures across callers:
    // 1) version
    // 2) destination_connection_id_len
    // 3) source_connection_id_len (or "na" when absent)
    // 4) packet_number_length
    let source_connection_id_len = metadata
        .source_connection_id_len
        .map(|v| v.to_string())
        .unwrap_or_else(|| "na".to_string());
    format!(
        "version={:08x};destination_connection_id_len={};source_connection_id_len={};packet_number_length={}",
        metadata.version.expect("version required for complete summary"),
        metadata
            .destination_connection_id_len
            .expect("destination_connection_id_len required for complete summary"),
        source_connection_id_len,
        metadata
            .packet_number_length
            .expect("packet_number_length required for complete summary")
    )
}

fn hash12(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let digest = hasher.finalize();
    hex_lower(&digest)[..12].to_string()
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

fn with_quic_transport_prefix(value: &str) -> Option<String> {
    if value.is_empty() {
        return None;
    }
    let mut chars = value.chars();
    chars.next()?;
    Some(format!("q{}", chars.as_str()))
}

fn unavailable_missing_required_data(computed_at: SystemTime) -> Fingerprint {
    Fingerprint {
        kind: FingerprintKind::Ja4One,
        availability: FingerprintAvailability::Unavailable,
        value: None,
        computed_at: Some(computed_at),
        failure_reason: Some(FingerprintFailureReason::MissingRequiredData),
    }
}
