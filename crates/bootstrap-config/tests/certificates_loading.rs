use fingerprint_proxy_bootstrap_config::certificates::load_tls_certificates;
use fingerprint_proxy_bootstrap_config::config::{
    BootstrapConfig, CertificateRef, DefaultCertificatePolicy, ListenerAcquisitionMode,
    ListenerConfig, ServerNamePattern, SystemLimits, SystemTimeouts, TlsCertificateConfig,
};
use fingerprint_proxy_core::error::ErrorKind;
use std::collections::BTreeMap;

fn base_bootstrap_config() -> BootstrapConfig {
    BootstrapConfig {
        listener_acquisition_mode: ListenerAcquisitionMode::DirectBind,
        listeners: vec![ListenerConfig {
            bind: "127.0.0.1:0".parse().expect("bind"),
        }],
        tls_certificates: Vec::new(),
        default_certificate_policy: DefaultCertificatePolicy::Reject,
        dynamic_provider: None,
        stats_api: fingerprint_proxy_bootstrap_config::config::StatsApiConfig {
            enabled: false,
            bind: "127.0.0.1:0".parse().expect("stats bind"),
            network_policy:
                fingerprint_proxy_bootstrap_config::config::StatsApiNetworkPolicy::Disabled,
            auth_policy: fingerprint_proxy_bootstrap_config::config::StatsApiAuthPolicy::Disabled,
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
    }
}

fn write_temp_file(name: &str, contents: &str) -> std::path::PathBuf {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut dir = std::env::temp_dir();
    dir.push(format!("fp-bootstrap-cert-tests-{id}"));
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
            .map(|s| s.to_string())
            .collect::<Vec<String>>(),
    );
    params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
    let cert = rcgen::Certificate::from_params(params).expect("leaf cert");
    let cert_pem = cert.serialize_pem_with_signer(ca).expect("leaf cert pem");
    let key_pem = cert.serialize_private_key_pem();
    (cert_pem, key_pem)
}

#[test]
fn loads_valid_chain_and_key_into_selection_config() {
    let ca = generate_ca();
    let (default_cert_pem, default_key_pem) = generate_leaf(&ca, vec!["default.test"]);
    let (example_cert_pem, example_key_pem) = generate_leaf(&ca, vec!["example.com"]);

    let default_cert_path = write_temp_file("default-cert.pem", &default_cert_pem);
    let default_key_path = write_temp_file("default-key.pem", &default_key_pem);
    let example_cert_path = write_temp_file("example-cert.pem", &example_cert_pem);
    let example_key_path = write_temp_file("example-key.pem", &example_key_pem);

    let mut cfg = base_bootstrap_config();
    cfg.default_certificate_policy = DefaultCertificatePolicy::UseDefault(CertificateRef {
        id: "default".to_string(),
    });
    cfg.tls_certificates = vec![
        TlsCertificateConfig {
            id: "default".to_string(),
            certificate_pem_path: default_cert_path.to_string_lossy().to_string(),
            private_key_pem_path: default_key_path.to_string_lossy().to_string(),
            server_names: Vec::new(),
        },
        TlsCertificateConfig {
            id: "example".to_string(),
            certificate_pem_path: example_cert_path.to_string_lossy().to_string(),
            private_key_pem_path: example_key_path.to_string_lossy().to_string(),
            server_names: vec![ServerNamePattern::Exact("example.com".to_string())],
        },
    ];

    let loaded = load_tls_certificates(&cfg).expect("load tls certs");
    assert!(loaded.keys_by_id.len() >= 2);
    assert_eq!(loaded.selection.certificates.len(), 2);
}

#[test]
fn missing_certificate_file_is_deterministic_error() {
    let ca = generate_ca();
    let (_cert_pem, key_pem) = generate_leaf(&ca, vec!["example.com"]);
    let key_path = write_temp_file("key.pem", &key_pem);

    let mut cfg = base_bootstrap_config();
    cfg.tls_certificates = vec![TlsCertificateConfig {
        id: "example".to_string(),
        certificate_pem_path: "/no/such/cert.pem".to_string(),
        private_key_pem_path: key_path.to_string_lossy().to_string(),
        server_names: vec![ServerNamePattern::Exact("example.com".to_string())],
    }];

    let err = load_tls_certificates(&cfg).expect_err("missing cert file must error");
    assert_eq!(err.kind, ErrorKind::ValidationFailed);
    assert!(err
        .message
        .contains("missing TLS certificate file: /no/such/cert.pem"));
}

#[test]
fn invalid_certificate_pem_is_deterministic_error() {
    let ca = generate_ca();
    let (_cert_pem, key_pem) = generate_leaf(&ca, vec!["example.com"]);
    let cert_path = write_temp_file("cert.pem", "not a pem");
    let key_path = write_temp_file("key.pem", &key_pem);

    let mut cfg = base_bootstrap_config();
    cfg.tls_certificates = vec![TlsCertificateConfig {
        id: "example".to_string(),
        certificate_pem_path: cert_path.to_string_lossy().to_string(),
        private_key_pem_path: key_path.to_string_lossy().to_string(),
        server_names: vec![ServerNamePattern::Exact("example.com".to_string())],
    }];

    let err = load_tls_certificates(&cfg).expect_err("invalid cert must error");
    assert_eq!(err.kind, ErrorKind::ValidationFailed);
    assert!(err.message.contains("invalid TLS certificate PEM:"));
}

#[test]
fn missing_private_key_pem_is_deterministic_error() {
    let ca = generate_ca();
    let (cert_pem, _key_pem) = generate_leaf(&ca, vec!["example.com"]);
    let cert_path = write_temp_file("cert.pem", &cert_pem);
    let key_path = write_temp_file("key.pem", "");

    let mut cfg = base_bootstrap_config();
    cfg.tls_certificates = vec![TlsCertificateConfig {
        id: "example".to_string(),
        certificate_pem_path: cert_path.to_string_lossy().to_string(),
        private_key_pem_path: key_path.to_string_lossy().to_string(),
        server_names: vec![ServerNamePattern::Exact("example.com".to_string())],
    }];

    let err = load_tls_certificates(&cfg).expect_err("missing key must error");
    assert_eq!(err.kind, ErrorKind::ValidationFailed);
    assert!(err.message.contains("missing TLS private key PEM:"));
}

#[test]
fn private_key_mismatch_is_deterministic_error() {
    let ca = generate_ca();
    let (_cert_pem_a, key_pem_a) = generate_leaf(&ca, vec!["a.example"]);
    let (cert_pem_b, _key_pem_b) = generate_leaf(&ca, vec!["b.example"]);

    let cert_path = write_temp_file("cert.pem", &cert_pem_b);
    let key_path = write_temp_file("key.pem", &key_pem_a);

    let mut cfg = base_bootstrap_config();
    cfg.tls_certificates = vec![TlsCertificateConfig {
        id: "mismatch".to_string(),
        certificate_pem_path: cert_path.to_string_lossy().to_string(),
        private_key_pem_path: key_path.to_string_lossy().to_string(),
        server_names: vec![ServerNamePattern::Exact("b.example".to_string())],
    }];

    let err = load_tls_certificates(&cfg).expect_err("mismatch must error");
    assert_eq!(err.kind, ErrorKind::ValidationFailed);
    assert!(err
        .message
        .contains("TLS private key does not match certificate:"));
}
