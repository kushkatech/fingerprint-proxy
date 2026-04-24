pub mod availability;
pub mod components;
pub mod protocol;
pub mod tcp_integration;
pub mod tls_integration;

use crate::availability::{FingerprintAvailability, FingerprintFailureReason};
use crate::ja4::Ja4Input;
use crate::ja4one::availability::{track_component_availability, Ja4OneComponentAvailability};
use crate::ja4one::components::{indicate_component_contributions, Ja4OneComponentContributions};
use crate::ja4one::protocol::{derive_protocol_characteristics, Ja4OneProtocolCharacteristics};
use crate::ja4one::tcp_integration::{integrate_ja4t_component, Ja4TComponentIntegration};
use crate::ja4one::tls_integration::{integrate_ja4_component, Ja4ComponentIntegration};
use crate::ja4t::Ja4TInput;
use crate::model::{FingerprintComputationMetadata, FingerprintComputationResult};
use fingerprint_proxy_core::fingerprint::{Fingerprint, FingerprintKind, Fingerprints};
pub use fingerprint_proxy_core::fingerprinting::Ja4OneInput;
use sha2::{Digest, Sha256};
use std::time::SystemTime;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ja4OneComputationContext {
    pub protocol: Option<Ja4OneProtocolCharacteristics>,
    pub ja4t_component: Ja4TComponentIntegration,
    pub ja4_component: Ja4ComponentIntegration,
    pub availability: Ja4OneComponentAvailability,
    pub contributions: Ja4OneComponentContributions,
}

pub fn compute_ja4one_only(
    input: Option<&Ja4OneInput>,
    computed_at: SystemTime,
) -> FingerprintComputationResult {
    let ja4one = compute_ja4one_fingerprint(input, computed_at);
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

pub fn compute_ja4one_fingerprint(
    input: Option<&Ja4OneInput>,
    computed_at: SystemTime,
) -> Fingerprint {
    compute_ja4one_fingerprint_with_components(input, None, None, computed_at).0
}

pub fn compute_ja4one_fingerprint_with_components(
    ja4one_input: Option<&Ja4OneInput>,
    ja4t_input: Option<&Ja4TInput>,
    ja4_input: Option<&Ja4Input>,
    computed_at: SystemTime,
) -> (Fingerprint, Ja4OneComputationContext) {
    let ja4t_component = integrate_ja4t_component(ja4t_input);
    let ja4_component = integrate_ja4_component(ja4_input);
    let protocol = ja4one_input.map(derive_protocol_characteristics);
    let availability = track_component_availability(
        ja4one_input.is_some(),
        &ja4t_component,
        &ja4_component,
        protocol.as_ref(),
    );
    let contributions = indicate_component_contributions(&availability);

    let context = Ja4OneComputationContext {
        protocol: protocol.clone(),
        ja4t_component,
        ja4_component,
        availability,
        contributions,
    };

    let Some(input) = ja4one_input else {
        return (
            Fingerprint {
                kind: FingerprintKind::Ja4One,
                availability: FingerprintAvailability::Unavailable,
                value: None,
                computed_at: Some(computed_at),
                failure_reason: Some(FingerprintFailureReason::MissingRequiredData),
            },
            context,
        );
    };

    let value = compute_ja4one_string(input, protocol.as_ref().expect("protocol for ja4one input"));
    (
        Fingerprint {
            kind: FingerprintKind::Ja4One,
            availability: FingerprintAvailability::Complete,
            value: Some(value),
            computed_at: Some(computed_at),
            failure_reason: None,
        },
        context,
    )
}

fn compute_ja4one_string(input: &Ja4OneInput, protocol: &Ja4OneProtocolCharacteristics) -> String {
    let sni_flag = if protocol.sni_present { 'd' } else { 'i' };

    let filtered_ciphers: Vec<u16> = input
        .cipher_suites
        .iter()
        .copied()
        .filter(|v| !is_grease(*v))
        .collect();
    let cipher_count = std::cmp::min(filtered_ciphers.len(), 99);
    let cipher_hash = hash_cipher_suites(&filtered_ciphers);

    let filtered_exts_for_count: Vec<u16> = input
        .extensions
        .iter()
        .copied()
        .filter(|v| !is_grease(*v))
        .filter(|v| !is_dynamic_extension(*v))
        .collect();
    let extension_count = std::cmp::min(filtered_exts_for_count.len(), 99);

    let extension_hash = hash_extensions(&filtered_exts_for_count);

    format!(
        "{}{}{}{:02}{:02}{}_{}_{}",
        protocol.transport_prefix,
        protocol.tls_version_part,
        sni_flag,
        cipher_count,
        extension_count,
        protocol.alpn_indicator,
        cipher_hash,
        extension_hash
    )
}

fn is_dynamic_extension(ext: u16) -> bool {
    matches!(ext, 0x0029 | 0x0023 | 0x0015)
}

fn is_grease(value: u16) -> bool {
    ((value >> 8) == (value & 0x00FF)) && ((value & 0x000F) == 0x000A)
}

fn hash_cipher_suites(ciphers: &[u16]) -> String {
    let mut parts: Vec<String> = ciphers.iter().map(|c| format!("{:04x}", c)).collect();
    parts.sort();
    hash_joined(&parts)
}

fn hash_extensions(extensions_for_count: &[u16]) -> String {
    let mut for_hash: Vec<u16> = extensions_for_count
        .iter()
        .copied()
        .filter(|e| *e != 0x0000 && *e != 0x0010)
        .collect();
    for_hash.sort_unstable();
    let parts: Vec<String> = for_hash.iter().map(|e| format!("{:04x}", e)).collect();
    hash_joined(&parts)
}

fn hash_joined(parts: &[String]) -> String {
    let joined = parts.join(",");
    let hash = Sha256::digest(joined.as_bytes());
    let first_six = &hash[..6];
    bytes_to_lower_hex(first_six)
}

fn bytes_to_lower_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}
