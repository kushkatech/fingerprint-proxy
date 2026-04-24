use fingerprint_proxy_fingerprinting::ja4::{compute_ja4_fingerprint, Ja4Input};
use fingerprint_proxy_fingerprinting::{FingerprintAvailability, FingerprintFailureReason};
use std::time::SystemTime;

#[test]
fn ja4_reference_vectors() {
    let now = SystemTime::UNIX_EPOCH;
    for vector in load_vectors() {
        let fingerprint = compute_ja4_fingerprint(Some(&vector.input), now);
        assert_eq!(
            fingerprint.availability,
            FingerprintAvailability::Complete,
            "{}",
            vector.name
        );
        assert_eq!(fingerprint.failure_reason, None, "{}", vector.name);
        assert_eq!(
            fingerprint.value.as_deref(),
            Some(vector.expected.as_str()),
            "{}",
            vector.name
        );
    }
}

#[test]
fn ja4_is_deterministic() {
    let now = SystemTime::UNIX_EPOCH;
    let vector = load_vectors()
        .into_iter()
        .next()
        .expect("at least one vector");
    let a = compute_ja4_fingerprint(Some(&vector.input), now);
    let b = compute_ja4_fingerprint(Some(&vector.input), now);
    assert_eq!(a.value, b.value);
    assert_eq!(a.availability, b.availability);
    assert_eq!(a.failure_reason, b.failure_reason);
}

#[test]
fn ja4_unavailable_when_version_missing() {
    let now = SystemTime::UNIX_EPOCH;
    let input = Ja4Input {
        tls_version: None,
        supported_versions: None,
        cipher_suites: Some(vec![0x1301]),
        extensions: Some(vec![0x0000]),
        alpn: Some(vec!["h2".to_string()]),
        alpn_raw: None,
        signature_algorithms: Some(vec![0x0403]),
    };
    let fp = compute_ja4_fingerprint(Some(&input), now);
    assert_eq!(fp.availability, FingerprintAvailability::Unavailable);
    assert_eq!(
        fp.failure_reason,
        Some(FingerprintFailureReason::MissingRequiredData)
    );
}

#[test]
fn ja4_unavailable_when_cipher_suites_missing() {
    let now = SystemTime::UNIX_EPOCH;
    let input = Ja4Input {
        tls_version: Some(0x0304),
        supported_versions: None,
        cipher_suites: None,
        extensions: Some(vec![0x0000]),
        alpn: Some(vec!["h2".to_string()]),
        alpn_raw: None,
        signature_algorithms: Some(vec![0x0403]),
    };
    let fp = compute_ja4_fingerprint(Some(&input), now);
    assert_eq!(fp.availability, FingerprintAvailability::Unavailable);
    assert_eq!(
        fp.failure_reason,
        Some(FingerprintFailureReason::MissingRequiredData)
    );
}

#[test]
fn ja4_unavailable_when_extensions_missing() {
    let now = SystemTime::UNIX_EPOCH;
    let input = Ja4Input {
        tls_version: Some(0x0304),
        supported_versions: None,
        cipher_suites: Some(vec![0x1301]),
        extensions: None,
        alpn: Some(vec!["h2".to_string()]),
        alpn_raw: None,
        signature_algorithms: Some(vec![0x0403]),
    };
    let fp = compute_ja4_fingerprint(Some(&input), now);
    assert_eq!(fp.availability, FingerprintAvailability::Unavailable);
    assert_eq!(
        fp.failure_reason,
        Some(FingerprintFailureReason::MissingRequiredData)
    );
}

#[test]
fn ja4_alpn_indicator_follows_official_alphanumeric_rules_for_strings() {
    assert_eq!(
        computed_alpn_indicator(Some(vec!["http/1.1".to_string()]), None),
        "h1"
    );
    assert_eq!(
        computed_alpn_indicator(Some(vec!["a".to_string()]), None),
        "aa"
    );
    assert_eq!(
        computed_alpn_indicator(Some(vec![String::new()]), None),
        "00"
    );
    assert_eq!(computed_alpn_indicator(None, None), "00");
}

#[test]
fn ja4_alpn_indicator_uses_raw_hex_fallback_for_non_alphanumeric_boundaries() {
    assert_eq!(computed_alpn_indicator(None, Some(vec![vec![0xab]])), "ab");
    assert_eq!(
        computed_alpn_indicator(None, Some(vec![vec![0xab, 0xcd]])),
        "ad"
    );
    assert_eq!(
        computed_alpn_indicator(None, Some(vec![vec![0x30, 0xab]])),
        "3b"
    );
    assert_eq!(
        computed_alpn_indicator(None, Some(vec![vec![0x30, 0x31, 0xab, 0xcd]])),
        "3d"
    );
    assert_eq!(
        computed_alpn_indicator(None, Some(vec![vec![0x30, 0xab, 0xcd, 0x31]])),
        "01"
    );
}

struct Ja4Vector {
    name: String,
    input: Ja4Input,
    expected: String,
}

fn load_vectors() -> Vec<Ja4Vector> {
    vec![
        Ja4Vector {
            name: "foxio_example_inline".to_string(),
            input: Ja4Input {
                tls_version: None,
                supported_versions: Some(vec![0x0304]),
                cipher_suites: Some(vec![
                    0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
                    0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
                ]),
                extensions: Some(vec![
                    0x001b, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d, 0x0005, 0x0023,
                    0x0012, 0x002b, 0xff01, 0x000b, 0x000a, 0x0015,
                ]),
                alpn: Some(vec!["h2".to_string()]),
                alpn_raw: None,
                signature_algorithms: Some(vec![
                    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
                ]),
            },
            expected: "t13d1516h2_8daaf6152771_e5627efa2ab1".to_string(),
        },
        Ja4Vector {
            name: "foxio_example_with_grease_inline".to_string(),
            input: Ja4Input {
                tls_version: None,
                supported_versions: Some(vec![0x0a0a, 0x0304]),
                cipher_suites: Some(vec![
                    0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8,
                    0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
                ]),
                extensions: Some(vec![
                    0x1a1a, 0x001b, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d, 0x0005,
                    0x0023, 0x0012, 0x002b, 0xff01, 0x000b, 0x000a, 0x0015,
                ]),
                alpn: Some(vec!["h2".to_string()]),
                alpn_raw: None,
                signature_algorithms: Some(vec![
                    0x2a2a, 0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
                ]),
            },
            expected: "t13d1516h2_8daaf6152771_e5627efa2ab1".to_string(),
        },
    ]
}

fn computed_alpn_indicator(alpn: Option<Vec<String>>, alpn_raw: Option<Vec<Vec<u8>>>) -> String {
    let now = SystemTime::UNIX_EPOCH;
    let input = Ja4Input {
        tls_version: Some(0x0304),
        supported_versions: None,
        cipher_suites: Some(vec![0x1301]),
        extensions: Some(vec![0x0000, 0x0010]),
        alpn,
        alpn_raw,
        signature_algorithms: Some(vec![0x0403]),
    };
    let fingerprint = compute_ja4_fingerprint(Some(&input), now);
    assert_eq!(fingerprint.availability, FingerprintAvailability::Complete);
    let value = fingerprint.value.expect("complete JA4 should have a value");
    value
        .split('_')
        .next()
        .expect("JA4 a-part should exist")
        .chars()
        .rev()
        .take(2)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect()
}
