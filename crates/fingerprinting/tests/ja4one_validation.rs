use fingerprint_proxy_core::fingerprint::{
    FingerprintAvailability, FingerprintFailureReason, FingerprintKind,
};
use fingerprint_proxy_fingerprinting::ja4::Ja4Input;
use fingerprint_proxy_fingerprinting::ja4one::{
    components::Ja4OneComponentKind, compute_ja4one_fingerprint,
    compute_ja4one_fingerprint_with_components, compute_ja4one_only, Ja4OneInput,
};
use fingerprint_proxy_fingerprinting::ja4t::Ja4TInput;
use std::time::SystemTime;

#[test]
fn spec_example_ja4one_string_matches() {
    // Spec §5.2.3 provides example inputs for cipher/extension hashing.
    // The example hash *values* in the spec appear inconsistent with SHA256; this test asserts
    // the algorithm-correct outputs for the spec's example inputs.
    let input = Ja4OneInput {
        tls_version: Some(0x0304),
        actual_tls_version: Some(0x0304),
        supported_versions: None,
        cipher_suites: vec![0x002f, 0x0033, 0x1301],
        extensions: vec![0x0000, 0x0010, 0x000a, 0x000d, 0x0017],
        alpn: vec!["h2".to_string()],
    };

    let fp = compute_ja4one_fingerprint(Some(&input), SystemTime::UNIX_EPOCH);
    assert_eq!(fp.kind, FingerprintKind::Ja4One);
    assert_eq!(fp.availability, FingerprintAvailability::Complete);
    let value = fp.value.unwrap();

    assert!(value.starts_with("t13d"));
    assert!(value.ends_with("_a576635e8910_2bd235b36552"));
}

#[test]
fn supported_versions_prefers_first_non_grease() {
    let input = Ja4OneInput {
        tls_version: Some(0x0303),
        actual_tls_version: None,
        supported_versions: Some(vec![0x0a0a, 0x0304]),
        cipher_suites: vec![],
        extensions: vec![],
        alpn: vec![],
    };

    let fp = compute_ja4one_fingerprint(Some(&input), SystemTime::UNIX_EPOCH);
    let value = fp.value.unwrap();
    assert!(value.starts_with("t13i"));
}

#[test]
fn missing_input_is_unavailable_missing_required_data() {
    let fp = compute_ja4one_fingerprint(None, SystemTime::UNIX_EPOCH);
    assert_eq!(fp.availability, FingerprintAvailability::Unavailable);
    assert_eq!(
        fp.failure_reason,
        Some(FingerprintFailureReason::MissingRequiredData)
    );
}

#[test]
fn compute_only_populates_ja4one_and_leaves_others_unavailable() {
    let input = Ja4OneInput {
        tls_version: None,
        actual_tls_version: None,
        supported_versions: None,
        cipher_suites: vec![],
        extensions: vec![],
        alpn: vec![],
    };
    let result = compute_ja4one_only(Some(&input), SystemTime::UNIX_EPOCH);
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
}

#[test]
fn component_availability_and_contributions_are_modeled_for_missing_integrations() {
    let ja4one_input = Ja4OneInput {
        tls_version: Some(0x0304),
        actual_tls_version: Some(0x0304),
        supported_versions: None,
        cipher_suites: vec![0x1301],
        extensions: vec![0x0000, 0x0010],
        alpn: vec!["h2".to_string()],
    };

    let (fingerprint, context) = compute_ja4one_fingerprint_with_components(
        Some(&ja4one_input),
        None,
        None,
        SystemTime::UNIX_EPOCH,
    );

    assert_eq!(fingerprint.availability, FingerprintAvailability::Complete);
    assert_eq!(
        context.availability.overall(),
        FingerprintAvailability::Partial
    );
    assert_eq!(
        context.contributions.unavailable,
        vec![Ja4OneComponentKind::Ja4T, Ja4OneComponentKind::Ja4]
    );
}

#[test]
fn component_availability_is_complete_when_ja4t_ja4_and_protocol_are_present() {
    let ja4one_input = Ja4OneInput {
        tls_version: Some(0x0304),
        actual_tls_version: Some(0x0304),
        supported_versions: None,
        cipher_suites: vec![0x1301, 0x1302],
        extensions: vec![0x0000, 0x0010, 0x000d],
        alpn: vec!["h2".to_string()],
    };
    let ja4t_input = Ja4TInput {
        window_size: Some(29200),
        option_kinds_in_order: vec![2, 4, 8, 1, 3],
        mss: Some(1424),
        window_scale: Some(7),
    };
    let ja4_input = Ja4Input {
        tls_version: Some(0x0304),
        supported_versions: None,
        cipher_suites: Some(vec![0x1301, 0x1302]),
        extensions: Some(vec![0x0000, 0x0010, 0x000d]),
        alpn: Some(vec!["h2".to_string()]),
        alpn_raw: None,
        signature_algorithms: Some(vec![0x0403]),
    };

    let (_fingerprint, context) = compute_ja4one_fingerprint_with_components(
        Some(&ja4one_input),
        Some(&ja4t_input),
        Some(&ja4_input),
        SystemTime::UNIX_EPOCH,
    );

    assert_eq!(
        context.availability.overall(),
        FingerprintAvailability::Complete
    );
    assert_eq!(
        context.contributions.contributing,
        vec![
            Ja4OneComponentKind::Ja4OneInput,
            Ja4OneComponentKind::Ja4T,
            Ja4OneComponentKind::Ja4,
            Ja4OneComponentKind::Protocol,
        ]
    );
    assert!(context.contributions.unavailable.is_empty());
    assert!(context.contributions.partial.is_empty());
}
