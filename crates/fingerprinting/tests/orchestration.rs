use fingerprint_proxy_core::fingerprint::{FingerprintAvailability, FingerprintFailureReason};
use fingerprint_proxy_fingerprinting::ja4::Ja4Input;
use fingerprint_proxy_fingerprinting::ja4one::Ja4OneInput;
use fingerprint_proxy_fingerprinting::ja4t::Ja4TInput;
use fingerprint_proxy_fingerprinting::model::{
    ConnectionTuple, FingerprintComputationInputs, FingerprintComputationRequest,
    Ja4OneComponentName, TransportHint,
};
use fingerprint_proxy_fingerprinting::orchestration::compute_all_fingerprints;
use std::net::{IpAddr, Ipv4Addr};
use std::time::SystemTime;

fn base_request() -> FingerprintComputationRequest {
    FingerprintComputationRequest {
        connection: ConnectionTuple {
            source_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            source_port: 12345,
            destination_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
            destination_port: 443,
            transport: TransportHint::Tcp,
        },
        inputs: FingerprintComputationInputs::default(),
        tls_client_hello: None,
        tcp_metadata: None,
        protocol_metadata: None,
        received_at: SystemTime::UNIX_EPOCH,
    }
}

fn example_ja4_inputs() -> (Ja4Input, Ja4OneInput) {
    let ja4 = Ja4Input {
        tls_version: None,
        supported_versions: Some(vec![0x0304]),
        cipher_suites: Some(vec![0x1301, 0x1302, 0x1303]),
        extensions: Some(vec![0x0000, 0x0010, 0x002b, 0x000d]),
        alpn: Some(vec!["h2".to_string()]),
        alpn_raw: None,
        signature_algorithms: Some(vec![0x0403]),
    };
    let ja4one = Ja4OneInput {
        tls_version: Some(0x0304),
        actual_tls_version: Some(0x0304),
        supported_versions: None,
        cipher_suites: vec![0x1301, 0x1302, 0x1303],
        extensions: vec![0x0000, 0x0010, 0x002b, 0x000d],
        alpn: vec!["h2".to_string()],
    };
    (ja4, ja4one)
}

#[test]
fn computes_all_three_when_inputs_present() {
    let (ja4, ja4one) = example_ja4_inputs();
    let ja4t = Ja4TInput {
        window_size: Some(29200),
        option_kinds_in_order: vec![2, 4, 8, 1, 3],
        mss: Some(1424),
        window_scale: Some(7),
    };

    let mut request = base_request();
    request.inputs.ja4t = Some(ja4t);
    request.inputs.ja4 = Some(ja4);
    request.inputs.ja4one = Some(ja4one);

    let result = compute_all_fingerprints(&request, SystemTime::UNIX_EPOCH);
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

    let ja4one_components = result
        .metadata
        .ja4one_components
        .as_ref()
        .expect("ja4one component context should be present");
    assert_eq!(
        ja4one_components.contributions.contributing,
        vec![
            Ja4OneComponentName::Ja4OneInput,
            Ja4OneComponentName::Ja4T,
            Ja4OneComponentName::Ja4,
            Ja4OneComponentName::Protocol,
        ]
    );
    assert!(ja4one_components.contributions.partial.is_empty());
    assert!(ja4one_components.contributions.unavailable.is_empty());
    assert!(result.fingerprints.ja4t.value.is_some());
    assert!(result.fingerprints.ja4.value.is_some());
    assert!(result.fingerprints.ja4one.value.is_some());
}

#[test]
fn missing_tcp_inputs_does_not_block_tls_fingerprints() {
    let (ja4, ja4one) = example_ja4_inputs();
    let mut request = base_request();
    request.inputs.ja4 = Some(ja4);
    request.inputs.ja4one = Some(ja4one);
    request.inputs.ja4t = None;

    let result = compute_all_fingerprints(&request, SystemTime::UNIX_EPOCH);
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
        FingerprintAvailability::Complete
    );
    assert_eq!(
        result.fingerprints.ja4one.availability,
        FingerprintAvailability::Complete
    );
}

#[test]
fn missing_tls_inputs_does_not_block_ja4t() {
    let ja4t = Ja4TInput {
        window_size: Some(29200),
        option_kinds_in_order: vec![2, 4, 8, 1, 3],
        mss: Some(1424),
        window_scale: Some(7),
    };

    let mut request = base_request();
    request.inputs.ja4t = Some(ja4t);
    request.inputs.ja4 = None;
    request.inputs.ja4one = None;

    let result = compute_all_fingerprints(&request, SystemTime::UNIX_EPOCH);
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

#[test]
fn determinism_same_input_same_output() {
    let (ja4, ja4one) = example_ja4_inputs();
    let ja4t = Ja4TInput {
        window_size: Some(29200),
        option_kinds_in_order: vec![2, 4, 8, 1, 3],
        mss: Some(1424),
        window_scale: Some(7),
    };

    let mut request = base_request();
    request.inputs.ja4t = Some(ja4t);
    request.inputs.ja4 = Some(ja4);
    request.inputs.ja4one = Some(ja4one);

    let a = compute_all_fingerprints(&request, SystemTime::UNIX_EPOCH);
    let b = compute_all_fingerprints(&request, SystemTime::UNIX_EPOCH);
    assert_eq!(a, b);
}
