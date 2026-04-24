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
        signature_algorithms: Some(vec![0x0403]),
    };
    let fp = compute_ja4_fingerprint(Some(&input), now);
    assert_eq!(fp.availability, FingerprintAvailability::Unavailable);
    assert_eq!(
        fp.failure_reason,
        Some(FingerprintFailureReason::MissingRequiredData)
    );
}

struct Ja4Vector {
    name: String,
    input: Ja4Input,
    expected: String,
}

fn load_vectors() -> Vec<Ja4Vector> {
    let raw = include_str!("../../../testdata/ja4/vectors.tsv");
    let mut out = Vec::new();
    for (idx, line) in raw.lines().enumerate() {
        if idx == 0 || line.trim().is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split('\t').collect();
        assert_eq!(parts.len(), 7, "vector line must have 7 columns: {line}");
        let name = parts[0].to_string();
        let supported_versions = parse_hex_u16_list(parts[1]);
        let cipher_suites = parse_hex_u16_list(parts[2]);
        let extensions = parse_hex_u16_list(parts[3]);
        let signature_algorithms = parse_hex_u16_list(parts[4]);
        let alpn = parse_string_list(parts[5]);
        let expected = parts[6].to_string();

        out.push(Ja4Vector {
            name,
            input: Ja4Input {
                tls_version: None,
                supported_versions: Some(supported_versions),
                cipher_suites: Some(cipher_suites),
                extensions: Some(extensions),
                alpn: Some(alpn),
                signature_algorithms: Some(signature_algorithms),
            },
            expected,
        });
    }
    out
}

fn parse_hex_u16_list(s: &str) -> Vec<u16> {
    let s = s.trim();
    if s.is_empty() {
        return Vec::new();
    }
    s.split(',')
        .map(|p| u16::from_str_radix(p.trim(), 16).expect("valid hex u16"))
        .collect()
}

fn parse_string_list(s: &str) -> Vec<String> {
    let s = s.trim();
    if s.is_empty() {
        return Vec::new();
    }
    s.split(',').map(|p| p.trim().to_string()).collect()
}
