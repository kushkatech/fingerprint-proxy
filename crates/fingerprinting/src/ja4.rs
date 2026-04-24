use crate::availability::{FingerprintAvailability, FingerprintFailureReason};
use crate::model::{FingerprintComputationMetadata, FingerprintComputationResult};
use fingerprint_proxy_core::fingerprint::{Fingerprint, FingerprintKind, Fingerprints};
pub use fingerprint_proxy_core::fingerprinting::Ja4Input;
use sha2::{Digest, Sha256};
use std::time::SystemTime;

pub fn compute_ja4_only(
    input: Option<&Ja4Input>,
    computed_at: SystemTime,
) -> FingerprintComputationResult {
    let ja4 = compute_ja4_fingerprint(input, computed_at);
    FingerprintComputationResult {
        fingerprints: Fingerprints {
            ja4t: Fingerprint::unavailable(FingerprintKind::Ja4T),
            ja4,
            ja4one: Fingerprint::unavailable(FingerprintKind::Ja4One),
        },
        metadata: FingerprintComputationMetadata {
            computed_at,
            ja4one_components: None,
        },
    }
}

pub fn compute_ja4_fingerprint(input: Option<&Ja4Input>, computed_at: SystemTime) -> Fingerprint {
    let Some(input) = input else {
        return Fingerprint {
            kind: FingerprintKind::Ja4,
            availability: FingerprintAvailability::Unavailable,
            value: None,
            computed_at: Some(computed_at),
            failure_reason: Some(FingerprintFailureReason::MissingRequiredData),
        };
    };

    let Some(version) = select_tls_version(input) else {
        return Fingerprint {
            kind: FingerprintKind::Ja4,
            availability: FingerprintAvailability::Unavailable,
            value: None,
            computed_at: Some(computed_at),
            failure_reason: Some(FingerprintFailureReason::MissingRequiredData),
        };
    };

    let Some(cipher_suites) = input.cipher_suites.as_ref() else {
        return Fingerprint {
            kind: FingerprintKind::Ja4,
            availability: FingerprintAvailability::Unavailable,
            value: None,
            computed_at: Some(computed_at),
            failure_reason: Some(FingerprintFailureReason::MissingRequiredData),
        };
    };

    let Some(extensions) = input.extensions.as_ref() else {
        return Fingerprint {
            kind: FingerprintKind::Ja4,
            availability: FingerprintAvailability::Unavailable,
            value: None,
            computed_at: Some(computed_at),
            failure_reason: Some(FingerprintFailureReason::MissingRequiredData),
        };
    };

    let value = compute_ja4_string(
        version,
        cipher_suites,
        extensions,
        input.alpn.as_deref(),
        input.alpn_raw.as_deref(),
        input.signature_algorithms.as_deref(),
    );

    Fingerprint {
        kind: FingerprintKind::Ja4,
        availability: FingerprintAvailability::Complete,
        value: Some(value),
        computed_at: Some(computed_at),
        failure_reason: None,
    }
}

fn compute_ja4_string(
    version: u16,
    cipher_suites: &[u16],
    extensions: &[u16],
    alpn: Option<&[String]>,
    alpn_raw: Option<&[Vec<u8>]>,
    signature_algorithms: Option<&[u16]>,
) -> String {
    let ja4_a = compute_a_part(version, cipher_suites, extensions, alpn, alpn_raw);
    let ja4_b = compute_b_part(cipher_suites);
    let ja4_c = compute_c_part(extensions, signature_algorithms.unwrap_or_default());
    format!("{ja4_a}_{ja4_b}_{ja4_c}")
}

fn compute_a_part(
    version: u16,
    cipher_suites: &[u16],
    extensions: &[u16],
    alpn: Option<&[String]>,
    alpn_raw: Option<&[Vec<u8>]>,
) -> String {
    let protocol = 't';
    let version_part = tls_version_to_part(version);
    let sni_flag = if extensions.contains(&0x0000) {
        'd'
    } else {
        'i'
    };

    let cipher_count = std::cmp::min(
        cipher_suites
            .iter()
            .copied()
            .filter(|v| !is_grease(*v))
            .count(),
        99,
    );
    let ext_count = std::cmp::min(
        extensions
            .iter()
            .copied()
            .filter(|v| !is_grease(*v))
            .count(),
        99,
    );

    let alpn_first2 = alpn_indicator(alpn, alpn_raw);
    format!("{protocol}{version_part}{sni_flag}{cipher_count:02}{ext_count:02}{alpn_first2}")
}

fn compute_b_part(cipher_suites: &[u16]) -> String {
    let mut filtered: Vec<u16> = cipher_suites
        .iter()
        .copied()
        .filter(|v| !is_grease(*v))
        .collect();
    filtered.sort_unstable();
    let input = join_hex_u16(&filtered);
    hash12(&input)
}

fn compute_c_part(extensions: &[u16], signature_algorithms: &[u16]) -> String {
    let mut filtered_exts: Vec<u16> = extensions
        .iter()
        .copied()
        .filter(|v| !is_grease(*v))
        .filter(|v| *v != 0x0000)
        .filter(|v| *v != 0x0010)
        .collect();
    filtered_exts.sort_unstable();
    let ext_part = join_hex_u16(&filtered_exts);

    let filtered_sigalgs: Vec<u16> = signature_algorithms
        .iter()
        .copied()
        .filter(|v| !is_grease(*v))
        .collect();
    let sigalg_part = join_hex_u16(&filtered_sigalgs);

    let input = format!("{ext_part}_{sigalg_part}");
    hash12(&input)
}

fn select_tls_version(input: &Ja4Input) -> Option<u16> {
    if let Some(supported) = input.supported_versions.as_ref() {
        let mut best: Option<u16> = None;
        for v in supported.iter().copied().filter(|v| !is_grease(*v)) {
            best = Some(match best {
                Some(current) => std::cmp::max(current, v),
                None => v,
            });
        }
        if best.is_some() {
            return best;
        }
    }

    match input.tls_version {
        Some(v) if !is_grease(v) => Some(v),
        _ => None,
    }
}

fn tls_version_to_part(version: u16) -> &'static str {
    match version {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        _ => "00",
    }
}

fn alpn_indicator(alpn: Option<&[String]>, alpn_raw: Option<&[Vec<u8>]>) -> String {
    if let Some(raw) = alpn_raw.and_then(|values| values.first()) {
        return alpn_indicator_from_bytes(raw);
    }
    alpn.and_then(|values| values.first())
        .map(|value| alpn_indicator_from_bytes(value.as_bytes()))
        .unwrap_or_else(|| "00".to_string())
}

fn alpn_indicator_from_bytes(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "00".to_string();
    }

    let Some(first_index) = bytes.iter().position(|byte| byte.is_ascii_alphanumeric()) else {
        return alpn_hex_fallback(bytes);
    };
    let Some(last_index) = bytes.iter().rposition(|byte| byte.is_ascii_alphanumeric()) else {
        return alpn_hex_fallback(bytes);
    };

    if first_index != 0 || last_index != bytes.len() - 1 {
        return alpn_hex_fallback(bytes);
    }

    let first = bytes[first_index];
    let last = bytes[last_index];
    let mut out = String::with_capacity(2);
    out.push(first as char);
    out.push(last as char);
    out
}

fn alpn_hex_fallback(bytes: &[u8]) -> String {
    let hex = hex_lower(bytes);
    let first = hex.as_bytes()[0] as char;
    let last = hex.as_bytes()[hex.len() - 1] as char;
    format!("{first}{last}")
}

fn is_grease(value: u16) -> bool {
    let hi = (value >> 8) as u8;
    let lo = (value & 0xFF) as u8;
    hi == lo && (lo & 0x0F) == 0x0A
}

fn join_hex_u16(values: &[u16]) -> String {
    values
        .iter()
        .map(|v| format!("{:04x}", v))
        .collect::<Vec<String>>()
        .join(",")
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
