use fingerprint_proxy_core::connection::{ConnectionContext, TransportProtocol};
use fingerprint_proxy_core::fingerprint::{
    Fingerprint, FingerprintAvailability, FingerprintFailureReason, FingerprintKind,
};
use fingerprint_proxy_core::fingerprinting::FingerprintComputationResult;
use fingerprint_proxy_core::identifiers::{ConfigVersion, ConnectionId, RequestId};
use fingerprint_proxy_core::request::{HttpRequest, HttpResponse};
use fingerprint_proxy_prepipeline::{build_request_context, PrePipelineInput};
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::SystemTime;

fn make_connection() -> ConnectionContext {
    let client = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 12345);
    let dest = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)), 443);
    ConnectionContext::new(
        ConnectionId(1),
        client,
        dest,
        TransportProtocol::Tcp,
        SystemTime::UNIX_EPOCH,
        ConfigVersion::new("cfg-1").expect("test config version"),
    )
}

fn make_result(
    ja4t_availability: FingerprintAvailability,
    ja4_availability: FingerprintAvailability,
    ja4one_availability: FingerprintAvailability,
    computed_at: SystemTime,
) -> FingerprintComputationResult {
    let ja4t = Fingerprint {
        kind: FingerprintKind::Ja4T,
        availability: ja4t_availability,
        value: Some("ja4t".to_string()),
        computed_at: Some(computed_at),
        failure_reason: match ja4t_availability {
            FingerprintAvailability::Unavailable => {
                Some(FingerprintFailureReason::MissingRequiredData)
            }
            _ => None,
        },
    };
    let ja4 = Fingerprint {
        kind: FingerprintKind::Ja4,
        availability: ja4_availability,
        value: Some("ja4".to_string()),
        computed_at: Some(computed_at),
        failure_reason: match ja4_availability {
            FingerprintAvailability::Unavailable => {
                Some(FingerprintFailureReason::MissingRequiredData)
            }
            _ => None,
        },
    };
    let ja4one = Fingerprint {
        kind: FingerprintKind::Ja4One,
        availability: ja4one_availability,
        value: Some("ja4one".to_string()),
        computed_at: Some(computed_at),
        failure_reason: match ja4one_availability {
            FingerprintAvailability::Unavailable => {
                Some(FingerprintFailureReason::MissingRequiredData)
            }
            _ => None,
        },
    };
    FingerprintComputationResult::from_parts(ja4t, ja4, ja4one, computed_at)
}

#[test]
fn build_request_context_sets_fingerprinting_result() {
    let computed_at = SystemTime::UNIX_EPOCH;
    let pre = PrePipelineInput {
        id: RequestId(1),
        connection: make_connection(),
        request: HttpRequest::new("GET", "/", "HTTP/1.1"),
        response: HttpResponse::default(),
        virtual_host: None,
        module_config: BTreeMap::new(),
        client_network_rules: Vec::new(),
        fingerprinting_result: make_result(
            FingerprintAvailability::Complete,
            FingerprintAvailability::Complete,
            FingerprintAvailability::Complete,
            computed_at,
        ),
    };

    let ctx = build_request_context(pre).expect("pre-pipeline assembly should succeed");
    let result = ctx
        .fingerprinting_result()
        .expect("fingerprinting_result must be set before pipeline");

    assert_eq!(
        result.fingerprints.ja4t.availability,
        FingerprintAvailability::Complete
    );
    assert_eq!(
        result.fingerprints.ja4.availability,
        FingerprintAvailability::Complete
    );
    assert_eq!(
        result.fingerprints.ja4one.availability,
        FingerprintAvailability::Complete
    );
}

#[test]
fn missing_inputs_are_represented_by_unavailable_result() {
    let computed_at = SystemTime::UNIX_EPOCH;
    let pre = PrePipelineInput {
        id: RequestId(1),
        connection: make_connection(),
        request: HttpRequest::new("GET", "/", "HTTP/1.1"),
        response: HttpResponse::default(),
        virtual_host: None,
        module_config: BTreeMap::new(),
        client_network_rules: Vec::new(),
        fingerprinting_result: make_result(
            FingerprintAvailability::Unavailable,
            FingerprintAvailability::Unavailable,
            FingerprintAvailability::Unavailable,
            computed_at,
        ),
    };

    let ctx = build_request_context(pre).expect("pre-pipeline assembly should succeed");
    let result = ctx
        .fingerprinting_result()
        .expect("fingerprinting_result must be present even when inputs are missing");

    assert_eq!(
        result.fingerprints.ja4t.availability,
        FingerprintAvailability::Unavailable
    );
    assert_eq!(
        result.fingerprints.ja4t.failure_reason,
        Some(FingerprintFailureReason::MissingRequiredData)
    );
    assert_eq!(
        result.fingerprints.ja4.availability,
        FingerprintAvailability::Unavailable
    );
    assert_eq!(
        result.fingerprints.ja4.failure_reason,
        Some(FingerprintFailureReason::MissingRequiredData)
    );
    assert_eq!(
        result.fingerprints.ja4one.availability,
        FingerprintAvailability::Unavailable
    );
    assert_eq!(
        result.fingerprints.ja4one.failure_reason,
        Some(FingerprintFailureReason::MissingRequiredData)
    );
}

#[test]
fn determinism_same_input_same_result() {
    let computed_at = SystemTime::UNIX_EPOCH;
    let pre = PrePipelineInput {
        id: RequestId(1),
        connection: make_connection(),
        request: HttpRequest::new("GET", "/", "HTTP/1.1"),
        response: HttpResponse::default(),
        virtual_host: None,
        module_config: BTreeMap::new(),
        client_network_rules: Vec::new(),
        fingerprinting_result: make_result(
            FingerprintAvailability::Complete,
            FingerprintAvailability::Complete,
            FingerprintAvailability::Complete,
            computed_at,
        ),
    };

    let a_ctx = build_request_context(pre.clone()).expect("pre-pipeline assembly should succeed");
    let b_ctx = build_request_context(pre).expect("pre-pipeline assembly should succeed");
    let a = a_ctx.fingerprinting_result().expect("result present");
    let b = b_ctx.fingerprinting_result().expect("result present");

    assert_eq!(a, b);
}
