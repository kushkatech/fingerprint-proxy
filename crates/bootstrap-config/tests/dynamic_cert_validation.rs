use fingerprint_proxy_bootstrap_config::certificates::{
    load_tls_certificates, LoadedTlsCertificates,
};
use fingerprint_proxy_bootstrap_config::config::{
    BootstrapConfig, CertificateRef, DefaultCertificatePolicy, DomainConfig,
    FingerprintHeaderConfig, FingerprintingConfig, Http2ServerPushPolicy, ListenerAcquisitionMode,
    ListenerConfig, ServerNamePattern, StatsApiAuthPolicy, StatsApiConfig, StatsApiNetworkPolicy,
    SystemLimits, SystemTimeouts, TlsCertificateConfig, TlsPrivateKeyFileProviderConfig,
    TlsPrivateKeyProviderConfig, UpstreamConfig, UpstreamProtocol, VirtualHostConfig,
    VirtualHostMatch, VirtualHostProtocolConfig, VirtualHostTlsConfig,
};
use fingerprint_proxy_bootstrap_config::dynamic::cert_validation::{
    validate_candidate_certificate_references, validate_retrieved_candidate_certificate_references,
};
use fingerprint_proxy_bootstrap_config::dynamic::validation::validate_candidate_domain_config;
use fingerprint_proxy_bootstrap_config::version_retrieval::VersionedConfig;
use fingerprint_proxy_bootstrap_config::versioning::ConfigRevisionId;
use fingerprint_proxy_core::error::ErrorKind;
use fingerprint_proxy_core::identifiers::ConfigVersion;
use std::collections::BTreeMap;

fn revision_id(value: &str) -> ConfigRevisionId {
    ConfigRevisionId::new(value).expect("valid revision id")
}

fn write_temp_file(name: &str, contents: &str) -> std::path::PathBuf {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut dir = std::env::temp_dir();
    dir.push(format!("fp-dynamic-cert-validation-{id}"));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let path = dir.join(name);
    std::fs::write(&path, contents).expect("write temp file");
    path
}

fn generate_ca() -> rcgen::Certificate {
    let mut params = rcgen::CertificateParams::new(Vec::new());
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
    rcgen::Certificate::from_params(params).expect("ca cert")
}

fn generate_leaf(ca: &rcgen::Certificate, names: Vec<&str>) -> (String, String) {
    let mut params = rcgen::CertificateParams::new(
        names
            .into_iter()
            .map(|name| name.to_string())
            .collect::<Vec<String>>(),
    );
    params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
    let cert = rcgen::Certificate::from_params(params).expect("leaf cert");
    let cert_pem = cert.serialize_pem_with_signer(ca).expect("leaf cert pem");
    let key_pem = cert.serialize_private_key_pem();
    (cert_pem, key_pem)
}

fn file_private_key_provider(path: impl Into<String>) -> TlsPrivateKeyProviderConfig {
    TlsPrivateKeyProviderConfig::File(TlsPrivateKeyFileProviderConfig {
        pem_path: path.into(),
    })
}

fn loaded_tls_certificates(cert_id: &str) -> LoadedTlsCertificates {
    let ca = generate_ca();
    let (cert_pem, key_pem) = generate_leaf(&ca, vec!["dynamic.example.com"]);
    let cert_path = write_temp_file("cert.pem", &cert_pem);
    let key_path = write_temp_file("key.pem", &key_pem);

    let bootstrap = BootstrapConfig {
        listener_acquisition_mode: ListenerAcquisitionMode::DirectBind,
        enable_http3_quic_listeners: false,
        fingerprinting: FingerprintingConfig::default(),
        listeners: vec![ListenerConfig {
            bind: "127.0.0.1:0".parse().expect("bind"),
        }],
        tls_certificates: vec![TlsCertificateConfig {
            id: cert_id.to_string(),
            certificate_pem_path: cert_path.to_string_lossy().to_string(),
            private_key_provider: file_private_key_provider(key_path.to_string_lossy().to_string()),
            server_names: vec![ServerNamePattern::Exact("dynamic.example.com".to_string())],
        }],
        default_certificate_policy: DefaultCertificatePolicy::UseDefault(CertificateRef {
            id: cert_id.to_string(),
        }),
        dynamic_provider: None,
        stats_api: StatsApiConfig {
            enabled: false,
            bind: "127.0.0.1:0".parse().expect("stats bind"),
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
        module_enabled: BTreeMap::new(),
    };

    load_tls_certificates(&bootstrap).expect("load TLS certificate material")
}

fn domain_config_with_cert(version: &str, cert_id: &str) -> DomainConfig {
    DomainConfig {
        version: ConfigVersion::new(version).expect("version"),
        virtual_hosts: vec![VirtualHostConfig {
            id: 11,
            match_criteria: VirtualHostMatch {
                sni: vec![ServerNamePattern::Exact("dynamic.example.com".to_string())],
                destination: Vec::new(),
            },
            tls: VirtualHostTlsConfig {
                certificate: CertificateRef {
                    id: cert_id.to_string(),
                },
                minimum_tls_version: None,
                cipher_suites: Vec::new(),
            },
            upstream: UpstreamConfig {
                protocol: UpstreamProtocol::Http,
                allowed_upstream_app_protocols: None,
                host: "upstream.internal".to_string(),
                port: 8080,
            },
            protocol: VirtualHostProtocolConfig {
                allow_http1: true,
                allow_http2: true,
                allow_http3: false,
                http2_server_push_policy: Http2ServerPushPolicy::Suppress,
            },
            module_config: BTreeMap::new(),
        }],
        fingerprint_headers: FingerprintHeaderConfig::default(),
        client_classification_rules: Vec::new(),
    }
}

#[test]
fn certificate_reference_validation_accepts_loaded_certificate_ids() {
    let loaded = loaded_tls_certificates("cert-a");
    let candidate =
        validate_candidate_domain_config(domain_config_with_cert("dyn-cert-1", "cert-a"))
            .expect("valid candidate");

    let validated =
        validate_candidate_certificate_references(candidate, &loaded).expect("certificate refs");
    assert_eq!(validated.revision_id().as_str(), "dyn-cert-1");
}

#[test]
fn certificate_reference_validation_rejects_missing_certificate_ids() {
    let loaded = loaded_tls_certificates("cert-a");
    let candidate =
        validate_candidate_domain_config(domain_config_with_cert("dyn-cert-2", "missing-cert"))
            .expect("valid candidate");

    let err = validate_candidate_certificate_references(candidate, &loaded)
        .expect_err("missing cert must fail");
    assert_eq!(err.kind, ErrorKind::ValidationFailed);
    assert!(err
        .message
        .contains("domain.virtual_hosts[0].tls.certificate.id"));
    assert!(err.message.contains("missing-cert"));
}

#[test]
fn retrieved_certificate_validation_preserves_non_found_variants() {
    let loaded = loaded_tls_certificates("cert-a");
    let unsupported = VersionedConfig::SpecificVersionUnsupported {
        requested: revision_id("dyn-cert-requested"),
        provider: "file",
    };

    let validated = validate_retrieved_candidate_certificate_references(unsupported, &loaded)
        .expect("pass-through unsupported");
    match validated {
        VersionedConfig::SpecificVersionUnsupported {
            requested,
            provider,
        } => {
            assert_eq!(requested.as_str(), "dyn-cert-requested");
            assert_eq!(provider, "file");
        }
        other => panic!("expected unsupported variant passthrough, got {other:?}"),
    }
}
