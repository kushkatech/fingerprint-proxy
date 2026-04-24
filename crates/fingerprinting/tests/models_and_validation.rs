use fingerprint_proxy_core::fingerprint::{
    Fingerprint, FingerprintAvailability, FingerprintKind, Fingerprints,
};
use fingerprint_proxy_fingerprinting::config::FingerprintHeaderConfig;
use fingerprint_proxy_fingerprinting::headers::plan_fingerprint_headers;
use fingerprint_proxy_fingerprinting::model::{
    ConnectionTuple, FingerprintComputationInputs, FingerprintComputationRequest, TransportHint,
};
use fingerprint_proxy_fingerprinting::validation::validate_fingerprinting_config;
use std::net::{IpAddr, Ipv4Addr};
use std::time::SystemTime;

#[test]
fn header_config_defaults_match_spec_defaults() {
    let cfg = FingerprintHeaderConfig::default();
    assert_eq!(cfg.ja4t_header, "X-JA4T");
    assert_eq!(cfg.ja4_header, "X-JA4");
    assert_eq!(cfg.ja4one_header, "X-JA4One");
}

#[test]
fn header_config_validation_rejects_empty_names() {
    let cfg = FingerprintHeaderConfig {
        ja4t_header: " ".to_string(),
        ja4_header: "".to_string(),
        ja4one_header: "\t".to_string(),
    };

    let report = validate_fingerprinting_config(&cfg);
    assert!(report.has_errors());
    assert!(report.issues.len() >= 3);
}

#[test]
fn header_plan_carries_availability_and_value_data_only() {
    let cfg = FingerprintHeaderConfig::default();

    let fingerprints = Fingerprints {
        ja4: Fingerprint {
            kind: FingerprintKind::Ja4,
            availability: FingerprintAvailability::Complete,
            value: Some("ja4-example".to_string()),
            computed_at: None,
            failure_reason: None,
        },
        ..Default::default()
    };

    let plan = plan_fingerprint_headers(&cfg, &fingerprints);
    assert_eq!(plan.ja4.0, "X-JA4");
    assert_eq!(plan.ja4.1.value.as_deref(), Some("ja4-example"));
    assert_eq!(plan.ja4.1.availability, FingerprintAvailability::Complete);
}

#[test]
fn computation_request_is_structural_only() {
    let req = FingerprintComputationRequest {
        connection: ConnectionTuple {
            source_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            source_port: 12345,
            destination_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
            destination_port: 443,
            transport: TransportHint::Tcp,
        },
        inputs: FingerprintComputationInputs::default(),
        tls_client_hello: Some(vec![1, 2, 3]),
        tcp_metadata: None,
        protocol_metadata: None,
        received_at: SystemTime::UNIX_EPOCH,
    };

    assert_eq!(req.connection.source_port, 12345);
    assert_eq!(req.tls_client_hello.as_deref(), Some(&[1, 2, 3][..]));
}
