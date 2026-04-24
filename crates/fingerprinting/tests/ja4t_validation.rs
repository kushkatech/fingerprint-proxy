use fingerprint_proxy_core::fingerprint::{
    FingerprintAvailability, FingerprintFailureReason, FingerprintKind,
};
use fingerprint_proxy_fingerprinting::ja4t::{
    compute_ja4t_fingerprint, compute_ja4t_only, Ja4TInput,
};
use std::time::SystemTime;

#[test]
fn complete_example_matches_expected_format() {
    // Approved normative example:
    // 29200_2-4-8-1-3_1424_7
    let input = Ja4TInput {
        window_size: Some(29200),
        option_kinds_in_order: vec![2, 4, 8, 1, 3],
        mss: Some(1424),
        window_scale: Some(7),
    };

    let fp = compute_ja4t_fingerprint(Some(&input), SystemTime::UNIX_EPOCH);
    assert_eq!(fp.kind, FingerprintKind::Ja4T);
    assert_eq!(fp.availability, FingerprintAvailability::Complete);
    assert_eq!(fp.value.as_deref(), Some("29200_2-4-8-1-3_1424_7"));
    assert_eq!(fp.failure_reason, None);
}

#[test]
fn partial_when_tcp_option_order_missing() {
    let input = Ja4TInput {
        window_size: Some(29200),
        option_kinds_in_order: vec![],
        mss: Some(1424),
        window_scale: Some(7),
    };

    let fp = compute_ja4t_fingerprint(Some(&input), SystemTime::UNIX_EPOCH);
    assert_eq!(fp.availability, FingerprintAvailability::Partial);
    assert_eq!(fp.value.as_deref(), Some("29200__1424_7"));
    assert_eq!(fp.failure_reason, None);
}

#[test]
fn partial_when_mss_missing() {
    let input = Ja4TInput {
        window_size: Some(29200),
        option_kinds_in_order: vec![2, 4, 8, 1, 3],
        mss: None,
        window_scale: Some(7),
    };

    let fp = compute_ja4t_fingerprint(Some(&input), SystemTime::UNIX_EPOCH);
    assert_eq!(fp.availability, FingerprintAvailability::Partial);
    assert_eq!(fp.value.as_deref(), Some("29200_2-4-8-1-3__7"));
}

#[test]
fn partial_when_window_scale_missing() {
    let input = Ja4TInput {
        window_size: Some(29200),
        option_kinds_in_order: vec![2, 4, 8, 1, 3],
        mss: Some(1424),
        window_scale: None,
    };

    let fp = compute_ja4t_fingerprint(Some(&input), SystemTime::UNIX_EPOCH);
    assert_eq!(fp.availability, FingerprintAvailability::Partial);
    assert_eq!(fp.value.as_deref(), Some("29200_2-4-8-1-3_1424_"));
}

#[test]
fn partial_when_both_mss_and_window_scale_missing() {
    let input = Ja4TInput {
        window_size: Some(29200),
        option_kinds_in_order: vec![2, 4, 8, 1, 3],
        mss: None,
        window_scale: None,
    };

    let fp = compute_ja4t_fingerprint(Some(&input), SystemTime::UNIX_EPOCH);
    assert_eq!(fp.availability, FingerprintAvailability::Partial);
    assert_eq!(fp.value.as_deref(), Some("29200_2-4-8-1-3__"));
}

#[test]
fn unavailable_when_window_size_missing() {
    let input = Ja4TInput {
        window_size: None,
        option_kinds_in_order: vec![2, 4],
        mss: Some(1460),
        window_scale: Some(7),
    };

    let fp = compute_ja4t_fingerprint(Some(&input), SystemTime::UNIX_EPOCH);
    assert_eq!(fp.availability, FingerprintAvailability::Unavailable);
    assert_eq!(fp.value, None);
    assert_eq!(
        fp.failure_reason,
        Some(FingerprintFailureReason::MissingRequiredData)
    );
}

#[test]
fn deterministic_for_identical_inputs() {
    let input = Ja4TInput {
        window_size: Some(1000),
        option_kinds_in_order: vec![1, 2, 3],
        mss: Some(1460),
        window_scale: Some(9),
    };

    let a = compute_ja4t_fingerprint(Some(&input), SystemTime::UNIX_EPOCH)
        .value
        .unwrap();
    let b = compute_ja4t_fingerprint(Some(&input), SystemTime::UNIX_EPOCH)
        .value
        .unwrap();
    assert_eq!(a, b);
}

#[test]
fn compute_only_populates_ja4t_and_leaves_others_unavailable() {
    let input = Ja4TInput {
        window_size: Some(1),
        option_kinds_in_order: vec![2],
        mss: Some(1460),
        window_scale: Some(0),
    };
    let result = compute_ja4t_only(Some(&input), SystemTime::UNIX_EPOCH);
    assert_eq!(
        result.fingerprints.ja4t.availability,
        FingerprintAvailability::Complete
    );
    assert_eq!(
        result.fingerprints.ja4.availability,
        FingerprintAvailability::Unavailable
    );
    assert_eq!(
        result.fingerprints.ja4one.availability,
        FingerprintAvailability::Unavailable
    );
}
