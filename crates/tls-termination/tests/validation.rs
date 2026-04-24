use fingerprint_proxy_core::error::IssueSeverity;
use fingerprint_proxy_tls_termination::config::{
    CertificateId, CertificateRef, DefaultCertificatePolicy, ServerNamePattern,
    TlsCertificateEntry, TlsSelectionConfig,
};
use fingerprint_proxy_tls_termination::validation::validate_tls_selection_config;

fn cert(id: &str) -> CertificateRef {
    CertificateRef {
        id: CertificateId::new(id).unwrap(),
    }
}

#[test]
fn empty_certificate_list_is_error_when_no_default() {
    let config = TlsSelectionConfig {
        default_policy: DefaultCertificatePolicy::Reject,
        certificates: vec![],
    };

    let report = validate_tls_selection_config(&config);
    assert!(report.has_errors());
}

#[test]
fn empty_certificate_list_is_warning_when_default_is_configured() {
    let config = TlsSelectionConfig {
        default_policy: DefaultCertificatePolicy::UseDefault(cert("default")),
        certificates: vec![],
    };

    let report = validate_tls_selection_config(&config);
    assert!(!report.has_errors());
    assert!(report
        .issues
        .iter()
        .any(|i| i.severity == IssueSeverity::Warning));
}

#[test]
fn reject_default_policy_is_warning() {
    let config = TlsSelectionConfig {
        default_policy: DefaultCertificatePolicy::Reject,
        certificates: vec![TlsCertificateEntry {
            certificate: cert("c1"),
            server_names: vec![ServerNamePattern::Exact("a.example.com".into())],
        }],
    };

    let report = validate_tls_selection_config(&config);
    assert!(!report.has_errors());
    assert!(report
        .issues
        .iter()
        .any(|i| i.severity == IssueSeverity::Warning));
}

#[test]
fn empty_pattern_is_error() {
    let config = TlsSelectionConfig {
        default_policy: DefaultCertificatePolicy::UseDefault(cert("default")),
        certificates: vec![TlsCertificateEntry {
            certificate: cert("c1"),
            server_names: vec![ServerNamePattern::WildcardSuffix("".into())],
        }],
    };

    let report = validate_tls_selection_config(&config);
    assert!(report.has_errors());
}
