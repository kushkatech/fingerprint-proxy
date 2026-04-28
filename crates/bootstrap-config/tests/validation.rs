use fingerprint_proxy_bootstrap_config::config::*;
use fingerprint_proxy_bootstrap_config::dynamic::upstream_check::UpstreamConnectivityValidationMode;
use fingerprint_proxy_bootstrap_config::validation::{
    validate_bootstrap_config, validate_domain_config, validate_http3_quic_listener_policy,
};
use fingerprint_proxy_core::identifiers::ConfigVersion;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

fn valid_bootstrap_config(
    dynamic_provider: Option<DynamicConfigProviderSettings>,
) -> BootstrapConfig {
    BootstrapConfig {
        listener_acquisition_mode: ListenerAcquisitionMode::DirectBind,
        enable_http3_quic_listeners: false,
        fingerprinting: FingerprintingConfig::default(),
        listeners: vec![ListenerConfig {
            bind: SocketAddr::from(([0, 0, 0, 0], 443)),
        }],
        tls_certificates: vec![],
        default_certificate_policy: DefaultCertificatePolicy::Reject,
        dynamic_provider,
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
    }
}

fn bootstrap_config_with_private_key_provider(
    provider: TlsPrivateKeyProviderConfig,
) -> BootstrapConfig {
    let mut config = valid_bootstrap_config(None);
    config.tls_certificates = vec![TlsCertificateConfig {
        id: "cert-1".to_string(),
        certificate_pem_path: "/certs/cert.pem".to_string(),
        private_key_provider: provider,
        server_names: vec![ServerNamePattern::Exact("example.com".to_string())],
    }];
    config
}

fn file_private_key_provider(path: impl Into<String>) -> TlsPrivateKeyProviderConfig {
    TlsPrivateKeyProviderConfig::File(TlsPrivateKeyFileProviderConfig {
        pem_path: path.into(),
    })
}

fn domain_config_with_http3(allow_http3: bool) -> DomainConfig {
    DomainConfig {
        version: ConfigVersion::new("v1").unwrap(),
        virtual_hosts: vec![VirtualHostConfig {
            id: 1,
            match_criteria: VirtualHostMatch {
                sni: vec![ServerNamePattern::Exact("example.com".into())],
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
                allow_http3,
                http2_server_push_policy: Http2ServerPushPolicy::Suppress,
            },
            module_config: Default::default(),
        }],
        fingerprint_headers: FingerprintHeaderConfig::default(),
        client_classification_rules: vec![],
    }
}

#[test]
fn bootstrap_requires_at_least_one_listener() {
    let config = BootstrapConfig {
        listener_acquisition_mode: ListenerAcquisitionMode::DirectBind,
        enable_http3_quic_listeners: false,
        fingerprinting: FingerprintingConfig::default(),
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
        enable_http3_quic_listeners: false,
        fingerprinting: FingerprintingConfig::default(),
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
fn bootstrap_warns_when_ja4t_missing_tcp_metadata_allows_unavailable() {
    let mut config = valid_bootstrap_config(None);
    config.fingerprinting.ja4t.missing_tcp_metadata_policy =
        Ja4TMissingTcpMetadataPolicy::AllowUnavailable;

    let report = validate_bootstrap_config(&config);

    assert!(!report.has_errors(), "{report}");
    assert!(report.issues.iter().any(|issue| {
        issue.severity == fingerprint_proxy_core::error::IssueSeverity::Warning
            && issue.path == "bootstrap.fingerprinting.ja4t.missing_tcp_metadata_policy"
            && issue
                .message
                .contains("intended only for testing/debugging")
            && issue.message.contains("JA4T will be unavailable")
            && issue
                .message
                .contains("saved-SYN capability cannot be acquired")
    }));
}

#[test]
fn bootstrap_rejects_enabled_stats_api_with_required_empty_controls() {
    let config = BootstrapConfig {
        listener_acquisition_mode: ListenerAcquisitionMode::DirectBind,
        enable_http3_quic_listeners: false,
        fingerprinting: FingerprintingConfig::default(),
        listeners: vec![ListenerConfig {
            bind: SocketAddr::from(([0, 0, 0, 0], 443)),
        }],
        tls_certificates: vec![],
        default_certificate_policy: DefaultCertificatePolicy::Reject,
        dynamic_provider: None,
        stats_api: StatsApiConfig {
            enabled: true,
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
    assert!(report.issues.iter().any(|issue| {
        issue.path == "bootstrap.stats_api.network_policy"
            && issue.message == "allowlist must be non-empty when network restrictions are required"
    }));
    assert!(report.issues.iter().any(|issue| {
        issue.path == "bootstrap.stats_api.auth_policy"
            && issue.message == "credentials must be non-empty when authentication is required"
    }));
}

#[test]
fn bootstrap_accepts_enabled_stats_api_with_required_controls_configured() {
    let config = BootstrapConfig {
        listener_acquisition_mode: ListenerAcquisitionMode::DirectBind,
        enable_http3_quic_listeners: false,
        fingerprinting: FingerprintingConfig::default(),
        listeners: vec![ListenerConfig {
            bind: SocketAddr::from(([0, 0, 0, 0], 443)),
        }],
        tls_certificates: vec![],
        default_certificate_policy: DefaultCertificatePolicy::Reject,
        dynamic_provider: None,
        stats_api: StatsApiConfig {
            enabled: true,
            bind: SocketAddr::from(([127, 0, 0, 1], 9000)),
            network_policy: StatsApiNetworkPolicy::RequireAllowlist(vec![Cidr {
                addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
                prefix_len: 32,
            }]),
            auth_policy: StatsApiAuthPolicy::RequireCredentials(vec![Credential::BearerToken(
                "secret".to_string(),
            )]),
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
    assert!(!report.has_errors(), "{report}");
}

#[test]
fn bootstrap_inherited_systemd_allows_empty_listeners() {
    let config = BootstrapConfig {
        listener_acquisition_mode: ListenerAcquisitionMode::InheritedSystemd,
        enable_http3_quic_listeners: false,
        fingerprinting: FingerprintingConfig::default(),
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
        enable_http3_quic_listeners: false,
        fingerprinting: FingerprintingConfig::default(),
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
fn bootstrap_inherited_systemd_rejects_http3_quic_listener_enablement() {
    let mut config = valid_bootstrap_config(None);
    config.listener_acquisition_mode = ListenerAcquisitionMode::InheritedSystemd;
    config.listeners.clear();
    config.enable_http3_quic_listeners = true;

    let report = validate_bootstrap_config(&config);

    assert!(report.has_errors());
    assert!(report.issues.iter().any(|issue| {
        issue.path == "bootstrap.enable_http3_quic_listeners"
            && issue.message == "HTTP/3 QUIC listeners are not supported in inherited_systemd mode"
    }));
}

#[test]
fn http3_quic_listener_policy_accepts_both_disabled() {
    let bootstrap = valid_bootstrap_config(None);
    let domain = domain_config_with_http3(false);

    let report = validate_http3_quic_listener_policy(&bootstrap, &domain);

    assert!(!report.has_errors(), "{report}");
}

#[test]
fn http3_quic_listener_policy_accepts_both_enabled() {
    let mut bootstrap = valid_bootstrap_config(None);
    bootstrap.enable_http3_quic_listeners = true;
    let domain = domain_config_with_http3(true);

    let report = validate_http3_quic_listener_policy(&bootstrap, &domain);

    assert!(!report.has_errors(), "{report}");
}

#[test]
fn http3_quic_listener_policy_rejects_http3_vhost_without_udp_enablement() {
    let bootstrap = valid_bootstrap_config(None);
    let domain = domain_config_with_http3(true);

    let report = validate_http3_quic_listener_policy(&bootstrap, &domain);

    assert!(report.has_errors());
    assert!(report.issues.iter().any(|issue| {
        issue.path == "bootstrap.enable_http3_quic_listeners"
            && issue.message
                == "one or more virtual hosts allow HTTP/3 but bootstrap HTTP/3 QUIC listeners are disabled"
    }));
}

#[test]
fn http3_quic_listener_policy_rejects_udp_enablement_without_http3_vhost() {
    let mut bootstrap = valid_bootstrap_config(None);
    bootstrap.enable_http3_quic_listeners = true;
    let domain = domain_config_with_http3(false);

    let report = validate_http3_quic_listener_policy(&bootstrap, &domain);

    assert!(report.has_errors());
    assert!(report.issues.iter().any(|issue| {
        issue.path == "bootstrap.enable_http3_quic_listeners"
            && issue.message
                == "bootstrap HTTP/3 QUIC listeners are enabled but no virtual host allows HTTP/3"
    }));
}

#[test]
fn bootstrap_dynamic_provider_accepts_file_kind() {
    let config = valid_bootstrap_config(Some(DynamicConfigProviderSettings {
        kind: FILE_DYNAMIC_PROVIDER_KIND.to_string(),
        polling_interval_seconds: DEFAULT_DYNAMIC_POLLING_INTERVAL_SECONDS,
        upstream_connectivity_validation_mode: UpstreamConnectivityValidationMode::Disabled,
    }));

    let report = validate_bootstrap_config(&config);

    assert!(!report.has_errors(), "{report}");
}

#[test]
fn bootstrap_dynamic_provider_rejects_non_file_kinds() {
    for kind in ["api", "db", "database", "unknown"] {
        let config = valid_bootstrap_config(Some(DynamicConfigProviderSettings {
            kind: kind.to_string(),
            polling_interval_seconds: DEFAULT_DYNAMIC_POLLING_INTERVAL_SECONDS,
            upstream_connectivity_validation_mode: UpstreamConnectivityValidationMode::Disabled,
        }));

        let report = validate_bootstrap_config(&config);

        assert!(report.has_errors(), "{kind} should fail validation");
        assert!(report.issues.iter().any(|issue| {
            issue.path == "bootstrap.dynamic_provider.kind"
                && issue.message
                    == format!(
                        "unsupported dynamic provider kind `{kind}`; only `file` is supported for active runtime dynamic configuration"
                    )
        }));
    }
}

#[test]
fn bootstrap_dynamic_provider_rejects_blank_kind() {
    let config = valid_bootstrap_config(Some(DynamicConfigProviderSettings {
        kind: " ".to_string(),
        polling_interval_seconds: DEFAULT_DYNAMIC_POLLING_INTERVAL_SECONDS,
        upstream_connectivity_validation_mode: UpstreamConnectivityValidationMode::Disabled,
    }));

    let report = validate_bootstrap_config(&config);

    assert!(report.has_errors());
    assert!(report.issues.iter().any(|issue| {
        issue.path == "bootstrap.dynamic_provider.kind"
            && issue.message
                == "provider kind must be non-empty when dynamic provider is configured"
    }));
}

#[test]
fn bootstrap_dynamic_provider_rejects_zero_polling_interval() {
    let config = valid_bootstrap_config(Some(DynamicConfigProviderSettings {
        kind: FILE_DYNAMIC_PROVIDER_KIND.to_string(),
        polling_interval_seconds: 0,
        upstream_connectivity_validation_mode: UpstreamConnectivityValidationMode::Disabled,
    }));

    let report = validate_bootstrap_config(&config);

    assert!(report.has_errors());
    assert!(report.issues.iter().any(|issue| {
        issue.path == "bootstrap.dynamic_provider.polling_interval_seconds"
            && issue.message == "dynamic polling interval must be greater than zero"
    }));
}

#[test]
fn bootstrap_accepts_file_private_key_provider() {
    let config = bootstrap_config_with_private_key_provider(file_private_key_provider(
        "/secret/private-key.pem".to_string(),
    ));

    let report = validate_bootstrap_config(&config);

    assert!(!report.has_errors(), "{report}");
}

#[test]
fn bootstrap_rejects_blank_file_private_key_provider_path_without_leakage() {
    let config =
        bootstrap_config_with_private_key_provider(file_private_key_provider("   ".to_string()));

    let report = validate_bootstrap_config(&config);

    assert!(report.has_errors());
    assert!(report.issues.iter().any(|issue| {
        issue.path == "bootstrap.tls_certificates[0].private_key_provider.pem_path"
            && issue.message == "file private key provider pem_path must be non-empty"
    }));
    assert!(!format!("{report}").contains("/secret/private-key.pem"));
}

#[test]
fn bootstrap_rejects_known_unsupported_private_key_provider_kinds() {
    for (kind, expected) in [
        (TlsPrivateKeyKnownUnsupportedProviderKind::Pkcs11, "pkcs11"),
        (TlsPrivateKeyKnownUnsupportedProviderKind::Kms, "kms"),
        (TlsPrivateKeyKnownUnsupportedProviderKind::Tpm, "tpm"),
    ] {
        let config = bootstrap_config_with_private_key_provider(
            TlsPrivateKeyProviderConfig::KnownUnsupported(kind),
        );

        let report = validate_bootstrap_config(&config);

        assert!(report.has_errors(), "{expected} should fail validation");
        assert!(report.issues.iter().any(|issue| {
            issue.path == "bootstrap.tls_certificates[0].private_key_provider.kind"
                && issue.message
                    == format!(
                        "private key provider kind `{expected}` is recognized but not supported in this build; only `file` is implemented"
                    )
        }));
    }
}

#[test]
fn bootstrap_rejects_unknown_private_key_provider_kind() {
    let config = bootstrap_config_with_private_key_provider(TlsPrivateKeyProviderConfig::Unknown(
        TlsPrivateKeyUnknownProviderConfig {
            kind: "vault".to_string(),
        },
    ));

    let report = validate_bootstrap_config(&config);

    assert!(report.has_errors());
    assert!(report.issues.iter().any(|issue| {
        issue.path == "bootstrap.tls_certificates[0].private_key_provider.kind"
            && issue.message
                == "unknown private key provider kind `vault`; supported kind is `file`; recognized-but-unsupported kinds are `pkcs11`, `kms`, `tpm`"
    }));
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
                    http2_server_push_policy: Http2ServerPushPolicy::Suppress,
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
                    http2_server_push_policy: Http2ServerPushPolicy::Suppress,
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

#[test]
fn domain_config_rejects_http2_server_push_forward_policy() {
    let mut config = domain_config_with_http3(false);
    config.virtual_hosts[0].protocol.http2_server_push_policy = Http2ServerPushPolicy::Forward;

    let report = validate_domain_config(&config);

    assert!(report.has_errors());
    assert!(report.issues.iter().any(|issue| {
        issue.path == "domain.virtual_hosts[0].protocol.http2_server_push_policy"
            && issue.message == "HTTP/2 server push forwarding is not supported; use suppress"
    }));
}
