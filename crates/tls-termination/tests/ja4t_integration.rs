use fingerprint_proxy_core::fingerprint::FingerprintAvailability;
use fingerprint_proxy_core::fingerprinting::{
    ConnectionTuple, FingerprintComputationInputs, FingerprintComputationRequest, Ja4TInput,
    TransportHint,
};
use fingerprint_proxy_tls_termination::{
    integrate_ja4t_connection_data, Ja4TIntegrationIssue, Ja4TIntegrationSource,
};
use std::net::{IpAddr, Ipv4Addr};
use std::time::SystemTime;

fn base_request() -> FingerprintComputationRequest {
    FingerprintComputationRequest {
        connection: ConnectionTuple {
            source_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            source_port: 44321,
            destination_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 30)),
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

#[test]
fn integration_derives_ja4t_input_from_connection_tcp_metadata() {
    let mut request = base_request();
    request.tcp_metadata = Some(b"snd_wnd=29200;tcp_options=2,4,8,1,3;mss=1424;wscale=7".to_vec());

    let outcome = integrate_ja4t_connection_data(&mut request);

    assert_eq!(outcome.availability, FingerprintAvailability::Complete);
    assert_eq!(
        outcome.source,
        Some(Ja4TIntegrationSource::ConnectionMetadata)
    );
    assert_eq!(outcome.issue, None);
    assert_eq!(
        request.inputs.ja4t,
        Some(Ja4TInput {
            window_size: Some(29200),
            option_kinds_in_order: vec![2, 4, 8, 1, 3],
            mss: Some(1424),
            window_scale: Some(7),
        })
    );
}

#[test]
fn integration_preserves_existing_request_ja4t_input() {
    let mut request = base_request();
    request.inputs.ja4t = Some(Ja4TInput {
        window_size: Some(12345),
        option_kinds_in_order: vec![2, 4],
        mss: Some(1460),
        window_scale: Some(8),
    });

    let outcome = integrate_ja4t_connection_data(&mut request);
    assert_eq!(outcome.availability, FingerprintAvailability::Complete);
    assert_eq!(outcome.source, Some(Ja4TIntegrationSource::RequestInput));
    assert_eq!(outcome.issue, None);
    assert_eq!(
        request.inputs.ja4t,
        Some(Ja4TInput {
            window_size: Some(12345),
            option_kinds_in_order: vec![2, 4],
            mss: Some(1460),
            window_scale: Some(8),
        })
    );
}

#[test]
fn integration_non_tcp_transport_is_deterministically_unavailable() {
    let mut request = base_request();
    request.connection.transport = TransportHint::Quic;

    let outcome = integrate_ja4t_connection_data(&mut request);

    assert_eq!(outcome.availability, FingerprintAvailability::Unavailable);
    assert_eq!(outcome.source, None);
    assert_eq!(outcome.issue, Some(Ja4TIntegrationIssue::NonTcpTransport));
    assert!(request.inputs.ja4t.is_none());
}
