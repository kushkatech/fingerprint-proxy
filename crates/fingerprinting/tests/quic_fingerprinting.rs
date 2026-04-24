use fingerprint_proxy_core::fingerprint::{
    FingerprintAvailability, FingerprintFailureReason, FingerprintKind,
};
use fingerprint_proxy_fingerprinting::quic::{
    compute_quic_ja4one_fingerprint, compute_quic_ja4one_only, compute_quic_metadata_signature,
    summarize_quic_metadata, QuicFingerprintMetadata,
};
use fingerprint_proxy_fingerprinting::Ja4OneInput;
use std::time::SystemTime;

fn base_ja4one_input() -> Ja4OneInput {
    Ja4OneInput {
        tls_version: Some(0x0304),
        actual_tls_version: Some(0x0304),
        supported_versions: None,
        cipher_suites: vec![0x1301, 0x1302, 0x1303],
        extensions: vec![0x0000, 0x0010, 0x002b, 0x000d],
        alpn: vec!["h3".to_string()],
    }
}

fn complete_quic_metadata() -> QuicFingerprintMetadata {
    QuicFingerprintMetadata {
        version: Some(0x00000001),
        destination_connection_id_len: Some(8),
        source_connection_id_len: Some(8),
        packet_number_length: Some(2),
    }
}

#[test]
fn quic_metadata_none_is_unavailable() {
    let summary = summarize_quic_metadata(None);
    assert_eq!(summary.availability, FingerprintAvailability::Unavailable);
    assert_eq!(
        summary.missing_required_fields,
        vec![
            "version",
            "destination_connection_id_len",
            "packet_number_length"
        ]
    );
}

#[test]
fn quic_metadata_partial_is_deterministic() {
    let summary = summarize_quic_metadata(Some(&QuicFingerprintMetadata {
        version: Some(0x00000001),
        destination_connection_id_len: None,
        source_connection_id_len: Some(8),
        packet_number_length: Some(2),
    }));
    assert_eq!(summary.availability, FingerprintAvailability::Partial);
    assert_eq!(
        summary.missing_required_fields,
        vec!["destination_connection_id_len"]
    );
}

#[test]
fn missing_inputs_are_unavailable() {
    let fp = compute_quic_ja4one_fingerprint(
        None,
        Some(&complete_quic_metadata()),
        SystemTime::UNIX_EPOCH,
    );
    assert_eq!(fp.kind, FingerprintKind::Ja4One);
    assert_eq!(fp.availability, FingerprintAvailability::Unavailable);
    assert_eq!(
        fp.failure_reason,
        Some(FingerprintFailureReason::MissingRequiredData)
    );
}

#[test]
fn missing_required_quic_metadata_is_unavailable() {
    let input = base_ja4one_input();
    let fp = compute_quic_ja4one_fingerprint(Some(&input), None, SystemTime::UNIX_EPOCH);
    assert_eq!(fp.kind, FingerprintKind::Ja4One);
    assert_eq!(fp.availability, FingerprintAvailability::Unavailable);
    assert_eq!(
        fp.failure_reason,
        Some(FingerprintFailureReason::MissingRequiredData)
    );
}

#[test]
fn partial_quic_metadata_keeps_value_but_marks_partial() {
    let input = base_ja4one_input();
    let metadata = QuicFingerprintMetadata {
        version: Some(0x00000001),
        destination_connection_id_len: None,
        source_connection_id_len: Some(8),
        packet_number_length: Some(2),
    };
    let fp = compute_quic_ja4one_fingerprint(Some(&input), Some(&metadata), SystemTime::UNIX_EPOCH);
    assert_eq!(fp.kind, FingerprintKind::Ja4One);
    assert_eq!(fp.availability, FingerprintAvailability::Partial);
    let value = fp
        .value
        .expect("partial fingerprint should still carry deterministic value");
    assert!(value.starts_with('q'));
    assert!(value.contains("h3_"));
}

#[test]
fn complete_quic_metadata_produces_q_prefixed_value() {
    let input = base_ja4one_input();
    let fp = compute_quic_ja4one_fingerprint(
        Some(&input),
        Some(&complete_quic_metadata()),
        SystemTime::UNIX_EPOCH,
    );
    assert_eq!(fp.kind, FingerprintKind::Ja4One);
    assert_eq!(fp.availability, FingerprintAvailability::Complete);
    let value = fp
        .value
        .expect("complete QUIC fingerprint should have a deterministic value");
    assert!(value.starts_with('q'));
    assert!(value.contains("h3_"));
}

#[test]
fn same_input_same_output_is_stable() {
    let input = base_ja4one_input();
    let metadata = complete_quic_metadata();

    let a = compute_quic_ja4one_fingerprint(Some(&input), Some(&metadata), SystemTime::UNIX_EPOCH);
    let b = compute_quic_ja4one_fingerprint(Some(&input), Some(&metadata), SystemTime::UNIX_EPOCH);
    assert_eq!(a, b);
}

#[test]
fn does_not_mutate_callers_input() {
    let input = base_ja4one_input();
    let metadata = complete_quic_metadata();
    let input_before = input.clone();
    let metadata_before = metadata.clone();

    let _ = compute_quic_ja4one_fingerprint(Some(&input), Some(&metadata), SystemTime::UNIX_EPOCH);
    assert_eq!(input, input_before);
    assert_eq!(metadata, metadata_before);
}

#[test]
fn compute_only_populates_ja4one_slot() {
    let input = base_ja4one_input();
    let result = compute_quic_ja4one_only(
        Some(&input),
        Some(&complete_quic_metadata()),
        SystemTime::UNIX_EPOCH,
    );
    assert_eq!(
        result.fingerprints.ja4t.availability,
        FingerprintAvailability::Unavailable
    );
    assert_eq!(
        result.fingerprints.ja4.availability,
        FingerprintAvailability::Unavailable
    );
    assert_eq!(
        result.fingerprints.ja4one.availability,
        FingerprintAvailability::Complete
    );
    let value = result
        .fingerprints
        .ja4one
        .value
        .expect("ja4one value should be present for complete quic metadata");
    assert!(value.starts_with('q'));
}

#[test]
fn quic_metadata_signature_is_stable_for_identical_input() {
    let metadata = complete_quic_metadata();
    let a = compute_quic_metadata_signature(Some(&metadata));
    let b = compute_quic_metadata_signature(Some(&metadata));

    assert_eq!(a.availability, FingerprintAvailability::Complete);
    assert_eq!(a, b);
    let value = a
        .value
        .expect("complete metadata signature should carry deterministic value");
    assert!(value.starts_with("qmeta1_"));
}

#[test]
fn quic_metadata_signature_changes_when_required_fields_change() {
    let base = complete_quic_metadata();
    let changed_version = QuicFingerprintMetadata {
        version: Some(0x00000002),
        ..base.clone()
    };
    let changed_dcid_len = QuicFingerprintMetadata {
        destination_connection_id_len: Some(12),
        ..base.clone()
    };
    let changed_packet_number_len = QuicFingerprintMetadata {
        packet_number_length: Some(4),
        ..base
    };

    let base_sig = compute_quic_metadata_signature(Some(&complete_quic_metadata()));
    let version_sig = compute_quic_metadata_signature(Some(&changed_version));
    let dcid_sig = compute_quic_metadata_signature(Some(&changed_dcid_len));
    let pn_sig = compute_quic_metadata_signature(Some(&changed_packet_number_len));

    assert_ne!(base_sig.value, version_sig.value);
    assert_ne!(base_sig.value, dcid_sig.value);
    assert_ne!(base_sig.value, pn_sig.value);
}

#[test]
fn quic_metadata_signature_missing_required_returns_unavailable_without_value() {
    let missing_version = QuicFingerprintMetadata {
        version: None,
        destination_connection_id_len: Some(8),
        source_connection_id_len: Some(8),
        packet_number_length: Some(2),
    };
    let signature = compute_quic_metadata_signature(Some(&missing_version));

    assert_eq!(signature.availability, FingerprintAvailability::Unavailable);
    assert_eq!(signature.value, None);
    assert_eq!(
        signature.failure_reason,
        Some(FingerprintFailureReason::MissingRequiredData)
    );
    assert_eq!(signature.missing_required_fields, vec!["version"]);
}

#[test]
fn quic_metadata_signature_none_returns_unavailable_without_value() {
    let signature = compute_quic_metadata_signature(None);
    assert_eq!(signature.availability, FingerprintAvailability::Unavailable);
    assert_eq!(signature.value, None);
    assert_eq!(
        signature.failure_reason,
        Some(FingerprintFailureReason::MissingRequiredData)
    );
    assert_eq!(
        signature.missing_required_fields,
        vec![
            "version",
            "destination_connection_id_len",
            "packet_number_length"
        ]
    );
}
