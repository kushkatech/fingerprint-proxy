use fingerprint_proxy_core::fingerprint::FingerprintAvailability;
use fingerprint_proxy_fingerprinting::model::{
    ConnectionTuple, FingerprintComputationInputs, FingerprintComputationRequest, TransportHint,
};
use fingerprint_proxy_fingerprinting::tcp::fallback::{
    derive_from_snapshot, TcpFallbackPolicy, TcpFallbackResult,
};
use fingerprint_proxy_fingerprinting::tcp::os_specific::{
    OsTcpMetadataInterface, StaticOsTcpMetadataInterface, TcpMetadataSnapshot,
};
use fingerprint_proxy_fingerprinting::tcp_data::{
    collect_ja4t_input, DefaultTcpDataCollector, TcpDataCollectionIssue, TcpDataCollector,
    TcpDataSource,
};
use fingerprint_proxy_fingerprinting::Ja4TInput;
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

#[test]
fn os_specific_interfaces_report_expected_capabilities() {
    let linux = StaticOsTcpMetadataInterface::linux().capabilities();
    assert!(linux.window_size);
    assert!(linux.option_kinds_in_order);
    assert!(linux.mss);
    assert!(linux.window_scale);

    let macos = StaticOsTcpMetadataInterface::macos().capabilities();
    assert!(macos.window_size);
    assert!(!macos.option_kinds_in_order);
    assert!(macos.mss);
    assert!(macos.window_scale);

    let windows = StaticOsTcpMetadataInterface::windows().capabilities();
    assert!(windows.window_size);
    assert!(!windows.option_kinds_in_order);
    assert!(!windows.mss);
    assert!(windows.window_scale);
}

#[test]
fn fallback_disabled_does_not_derive_input() {
    let snapshot = TcpMetadataSnapshot {
        window_size: Some(29200),
        option_kinds_in_order: None,
        mss: Some(1424),
        window_scale: Some(7),
    };

    let result = derive_from_snapshot(&snapshot, TcpFallbackPolicy::Disabled);
    assert_eq!(result, TcpFallbackResult::Unavailable);
}

#[test]
fn fallback_allow_empty_option_kinds_derives_deterministic_input() {
    let snapshot = TcpMetadataSnapshot {
        window_size: Some(29200),
        option_kinds_in_order: None,
        mss: Some(1424),
        window_scale: Some(7),
    };

    let result = derive_from_snapshot(&snapshot, TcpFallbackPolicy::AllowEmptyOptionKinds);
    let TcpFallbackResult::Derived(input) = result else {
        panic!("expected fallback-derived input");
    };

    assert_eq!(input.window_size, Some(29200));
    assert!(input.option_kinds_in_order.is_empty());
    assert_eq!(input.mss, Some(1424));
    assert_eq!(input.window_scale, Some(7));

    let fp = fingerprint_proxy_fingerprinting::compute_ja4t_fingerprint(
        Some(&input),
        SystemTime::UNIX_EPOCH,
    );
    assert_eq!(fp.availability, FingerprintAvailability::Partial);
}

#[test]
fn collector_prefers_request_input_when_present() {
    let mut request = base_request();
    request.inputs.ja4t = Some(Ja4TInput {
        window_size: Some(1234),
        option_kinds_in_order: vec![2, 4],
        mss: Some(1460),
        window_scale: Some(8),
    });
    request.tcp_metadata = Some(b"snd_wnd=29200;tcp_options=2,4,8,1,3;mss=1424;wscale=7".to_vec());

    let collector = DefaultTcpDataCollector::new(
        StaticOsTcpMetadataInterface::linux(),
        TcpFallbackPolicy::AllowEmptyOptionKinds,
    );
    let result = collector.collect(&request);

    assert_eq!(result.source, Some(TcpDataSource::RequestInput));
    assert_eq!(result.availability, FingerprintAvailability::Complete);
    assert_eq!(result.issue, None);
    assert_eq!(
        result.ja4t_input.expect("ja4t input").option_kinds_in_order,
        vec![2, 4]
    );
}

#[test]
fn collector_uses_os_metadata_when_available() {
    let mut request = base_request();
    request.tcp_metadata = Some(b"snd_wnd=29200;tcp_options=2,4,8,1,3;mss=1424;wscale=7".to_vec());

    let result = collect_ja4t_input(
        &request,
        &StaticOsTcpMetadataInterface::linux(),
        TcpFallbackPolicy::Disabled,
    );

    assert_eq!(result.source, Some(TcpDataSource::OsMetadata));
    assert_eq!(result.availability, FingerprintAvailability::Complete);
    assert_eq!(result.issue, None);
    let input = result.ja4t_input.expect("ja4t input");
    assert_eq!(input.window_size, Some(29200));
    assert_eq!(input.option_kinds_in_order, vec![2, 4, 8, 1, 3]);
    assert_eq!(input.mss, Some(1424));
    assert_eq!(input.window_scale, Some(7));
}

#[test]
fn collector_uses_fallback_when_os_interface_lacks_option_order() {
    let mut request = base_request();
    request.tcp_metadata = Some(b"window_size=29200;mss=1424;window_scale=7".to_vec());

    let result = collect_ja4t_input(
        &request,
        &StaticOsTcpMetadataInterface::macos(),
        TcpFallbackPolicy::AllowEmptyOptionKinds,
    );

    assert_eq!(result.source, Some(TcpDataSource::Fallback));
    assert_eq!(result.availability, FingerprintAvailability::Partial);
    assert_eq!(result.issue, None);
    assert!(result
        .ja4t_input
        .expect("ja4t input")
        .option_kinds_in_order
        .is_empty());
}

#[test]
fn collector_returns_unavailable_for_non_tcp_transport() {
    let mut request = base_request();
    request.connection.transport = TransportHint::Quic;

    let result = collect_ja4t_input(
        &request,
        &StaticOsTcpMetadataInterface::linux(),
        TcpFallbackPolicy::AllowEmptyOptionKinds,
    );

    assert_eq!(result.availability, FingerprintAvailability::Unavailable);
    assert_eq!(result.source, None);
    assert_eq!(result.issue, Some(TcpDataCollectionIssue::NonTcpTransport));
}

#[test]
fn collector_returns_deterministic_parse_failure() {
    let mut request = base_request();
    request.tcp_metadata = Some(b"snd_wnd=abc;tcp_options=2,4".to_vec());

    let result = collect_ja4t_input(
        &request,
        &StaticOsTcpMetadataInterface::linux(),
        TcpFallbackPolicy::AllowEmptyOptionKinds,
    );

    assert_eq!(result.availability, FingerprintAvailability::Unavailable);
    assert_eq!(result.source, None);
    assert_eq!(
        result.issue,
        Some(TcpDataCollectionIssue::MetadataParseFailed)
    );
}

#[test]
fn collector_fallback_disabled_is_explicitly_unavailable() {
    let mut request = base_request();
    request.tcp_metadata = Some(b"window_size=29200;mss=1424;window_scale=7".to_vec());

    let result = collect_ja4t_input(
        &request,
        &StaticOsTcpMetadataInterface::macos(),
        TcpFallbackPolicy::Disabled,
    );

    assert_eq!(result.availability, FingerprintAvailability::Unavailable);
    assert_eq!(result.source, None);
    assert_eq!(
        result.issue,
        Some(TcpDataCollectionIssue::FallbackUnavailable)
    );
}
