use fingerprint_proxy_bootstrap_config::config::*;
use fingerprint_proxy_bootstrap_config::validation::{
    validate_bootstrap_config, validate_domain_config,
};
use fingerprint_proxy_core::identifiers::ConfigVersion;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[test]
fn bootstrap_requires_at_least_one_listener() {
    let config = BootstrapConfig {
        listener_acquisition_mode: ListenerAcquisitionMode::DirectBind,
        listeners: vec![],
        tls_certificates: vec![],
        default_certificate_policy: DefaultCertificatePolicy::Reject,
        dynamic_provider: None,
        stats_api: StatsApiConfig {
            enabled: false,
            bind: SocketAddr::from(([127, 0, 0, 1], 9000)),
            network_policy: StatsApiNetworkPolicy::RequireAllowlist(vec![]),
            auth_policy: StatsApiAuthPolicy::RequireCredentials(vec![]),
        },
        timeouts: SystemTimeouts {
            upstream_connect_timeout: None,
            request_timeout: None,
        },
        limits: SystemLimits {
            max_header_bytes: None,
            max_body_bytes: None,
        },
        module_enabled: Default::default(),
    };

    let report = validate_bootstrap_config(&config);
    assert!(report.has_errors());
}

#[test]
fn bootstrap_warns_when_stats_api_controls_disabled() {
    let config = BootstrapConfig {
        listener_acquisition_mode: ListenerAcquisitionMode::DirectBind,
        listeners: vec![ListenerConfig {
            bind: SocketAddr::from(([0, 0, 0, 0], 443)),
        }],
        tls_certificates: vec![],
        default_certificate_policy: DefaultCertificatePolicy::Reject,
        dynamic_provider: None,
        stats_api: StatsApiConfig {
            enabled: true,
            bind: SocketAddr::from(([127, 0, 0, 1], 9000)),
            network_policy: StatsApiNetworkPolicy::Disabled,
            auth_policy: StatsApiAuthPolicy::Disabled,
        },
        timeouts: SystemTimeouts {
            upstream_connect_timeout: None,
            request_timeout: None,
        },
        limits: SystemLimits {
            max_header_bytes: None,
            max_body_bytes: None,
        },
        module_enabled: Default::default(),
    };

    let report = validate_bootstrap_config(&config);
    assert!(!report.has_errors());
    assert!(report
        .issues
        .iter()
        .any(|i| i.severity == fingerprint_proxy_core::error::IssueSeverity::Warning));
}

#[test]
fn bootstrap_inherited_systemd_allows_empty_listeners() {
    let config = BootstrapConfig {
        listener_acquisition_mode: ListenerAcquisitionMode::InheritedSystemd,
        listeners: vec![],
        tls_certificates: vec![],
        default_certificate_policy: DefaultCertificatePolicy::Reject,
        dynamic_provider: None,
        stats_api: StatsApiConfig {
            enabled: false,
            bind: SocketAddr::from(([127, 0, 0, 1], 9000)),
            network_policy: StatsApiNetworkPolicy::RequireAllowlist(vec![]),
            auth_policy: StatsApiAuthPolicy::RequireCredentials(vec![]),
        },
        timeouts: SystemTimeouts {
            upstream_connect_timeout: None,
            request_timeout: None,
        },
        limits: SystemLimits {
            max_header_bytes: None,
            max_body_bytes: None,
        },
        module_enabled: Default::default(),
    };

    let report = validate_bootstrap_config(&config);
    assert!(!report.has_errors());
}

#[test]
fn bootstrap_inherited_systemd_rejects_configured_listeners() {
    let config = BootstrapConfig {
        listener_acquisition_mode: ListenerAcquisitionMode::InheritedSystemd,
        listeners: vec![ListenerConfig {
            bind: SocketAddr::from(([127, 0, 0, 1], 9443)),
        }],
        tls_certificates: vec![],
        default_certificate_policy: DefaultCertificatePolicy::Reject,
        dynamic_provider: None,
        stats_api: StatsApiConfig {
            enabled: false,
            bind: SocketAddr::from(([127, 0, 0, 1], 9000)),
            network_policy: StatsApiNetworkPolicy::RequireAllowlist(vec![]),
            auth_policy: StatsApiAuthPolicy::RequireCredentials(vec![]),
        },
        timeouts: SystemTimeouts {
            upstream_connect_timeout: None,
            request_timeout: None,
        },
        limits: SystemLimits {
            max_header_bytes: None,
            max_body_bytes: None,
        },
        module_enabled: Default::default(),
    };

    let report = validate_bootstrap_config(&config);
    assert!(report.has_errors());
    assert!(report
        .issues
        .iter()
        .any(|i| i.message == "listeners must be empty in inherited_systemd mode"));
}

#[test]
fn domain_config_errors_on_multiple_default_virtual_hosts() {
    let config = DomainConfig {
        version: ConfigVersion::new("v1").unwrap(),
        virtual_hosts: vec![
            VirtualHostConfig {
                id: 1,
                match_criteria: VirtualHostMatch {
                    sni: vec![],
                    destination: vec![],
                },
                tls: VirtualHostTlsConfig {
                    certificate: CertificateRef {
                        id: "cert-1".into(),
                    },
                    minimum_tls_version: None,
                    cipher_suites: vec![],
                },
                upstream: UpstreamConfig {
                    protocol: UpstreamProtocol::Http,
                    allowed_upstream_app_protocols: None,
                    host: "example.internal".into(),
                    port: 8080,
                },
                protocol: VirtualHostProtocolConfig {
                    allow_http1: true,
                    allow_http2: true,
                    allow_http3: true,
                },
                module_config: Default::default(),
            },
            VirtualHostConfig {
                id: 2,
                match_criteria: VirtualHostMatch {
                    sni: vec![],
                    destination: vec![],
                },
                tls: VirtualHostTlsConfig {
                    certificate: CertificateRef {
                        id: "cert-2".into(),
                    },
                    minimum_tls_version: None,
                    cipher_suites: vec![],
                },
                upstream: UpstreamConfig {
                    protocol: UpstreamProtocol::Http,
                    allowed_upstream_app_protocols: None,
                    host: "example2.internal".into(),
                    port: 8081,
                },
                protocol: VirtualHostProtocolConfig {
                    allow_http1: true,
                    allow_http2: true,
                    allow_http3: true,
                },
                module_config: Default::default(),
            },
        ],
        fingerprint_headers: FingerprintHeaderConfig::default(),
        client_classification_rules: vec![ClientClassificationRule {
            name: "test".into(),
            cidrs: vec![Cidr {
                addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
                prefix_len: 8,
            }],
        }],
    };

    let report = validate_domain_config(&config);
    assert!(report.has_errors());
    assert!(report
        .issues
        .iter()
        .any(|i| i.message.contains("multiple default virtual hosts")
            && i.severity == fingerprint_proxy_core::error::IssueSeverity::Error));
}
