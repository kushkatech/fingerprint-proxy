use crate::ja4one::components::Ja4OneComponentKind;
use crate::ja4one::Ja4OneComputationContext;
use crate::model::{
    ConnectionTuple, FingerprintComputationInputs, FingerprintComputationRequest,
    FingerprintComputationResult, Ja4OneComponentAvailabilitySummary, Ja4OneComponentContext,
    Ja4OneComponentContributionSummary, Ja4OneComponentName,
};
use crate::orchestration::compute_all_fingerprints;
use crate::tls_data::TlsClientHelloData;
use fingerprint_proxy_core::fingerprinting::{Ja4Input, Ja4OneInput};
use std::time::SystemTime;

pub fn build_runtime_fingerprinting_request(
    connection: ConnectionTuple,
    tls_data: Option<&TlsClientHelloData>,
    received_at: SystemTime,
) -> FingerprintComputationRequest {
    let inputs = tls_data.map_or_else(FingerprintComputationInputs::default, |tls| {
        FingerprintComputationInputs {
            ja4t: None,
            ja4: Some(Ja4Input {
                tls_version: Some(tls.legacy_tls_version),
                supported_versions: tls.supported_versions.clone(),
                cipher_suites: Some(tls.cipher_suites.clone()),
                extensions: Some(tls.extensions.clone()),
                alpn: Some(tls.alpn_protocols.clone()),
                alpn_raw: Some(tls.alpn_protocols_raw.clone()),
                signature_algorithms: tls.signature_algorithms.clone(),
            }),
            ja4one: Some(Ja4OneInput {
                tls_version: Some(tls.legacy_tls_version),
                actual_tls_version: None,
                supported_versions: tls.supported_versions.clone(),
                cipher_suites: tls.cipher_suites.clone(),
                extensions: tls.extensions.clone(),
                alpn: tls.alpn_protocols.clone(),
            }),
        }
    });

    FingerprintComputationRequest {
        connection,
        inputs,
        tls_client_hello: tls_data.map(|tls| tls.raw_client_hello.clone()),
        tcp_metadata: None,
        protocol_metadata: None,
        received_at,
    }
}

pub fn compute_runtime_fingerprinting_result(
    connection: ConnectionTuple,
    tls_data: Option<&TlsClientHelloData>,
    computed_at: SystemTime,
) -> FingerprintComputationResult {
    let request = build_runtime_fingerprinting_request(connection, tls_data, computed_at);
    compute_all_fingerprints(&request, computed_at)
}

pub fn propagate_ja4one_component_context(
    context: &Ja4OneComputationContext,
) -> Ja4OneComponentContext {
    Ja4OneComponentContext {
        availability: Ja4OneComponentAvailabilitySummary {
            ja4one_input: context.availability.ja4one_input,
            ja4t: context.availability.ja4t_component,
            ja4: context.availability.ja4_component,
            protocol: context.availability.protocol_component,
        },
        contributions: Ja4OneComponentContributionSummary {
            contributing: context
                .contributions
                .contributing
                .iter()
                .map(|v| map_component_kind(*v))
                .collect(),
            partial: context
                .contributions
                .partial
                .iter()
                .map(|v| map_component_kind(*v))
                .collect(),
            unavailable: context
                .contributions
                .unavailable
                .iter()
                .map(|v| map_component_kind(*v))
                .collect(),
        },
    }
}

fn map_component_kind(kind: Ja4OneComponentKind) -> Ja4OneComponentName {
    match kind {
        Ja4OneComponentKind::Ja4OneInput => Ja4OneComponentName::Ja4OneInput,
        Ja4OneComponentKind::Ja4T => Ja4OneComponentName::Ja4T,
        Ja4OneComponentKind::Ja4 => Ja4OneComponentName::Ja4,
        Ja4OneComponentKind::Protocol => Ja4OneComponentName::Protocol,
    }
}
