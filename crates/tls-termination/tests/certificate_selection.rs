use fingerprint_proxy_tls_termination::certificate::{
    select_certificate, CertificateSelectionError,
};
use fingerprint_proxy_tls_termination::config::{
    CertificateId, CertificateRef, DefaultCertificatePolicy, ServerNamePattern,
    TlsCertificateEntry, TlsSelectionConfig,
};

fn cert(id: &str) -> CertificateRef {
    CertificateRef {
        id: CertificateId::new(id).unwrap(),
    }
}

#[test]
fn selects_exact_match_before_wildcard() {
    let config = TlsSelectionConfig {
        default_policy: DefaultCertificatePolicy::Reject,
        certificates: vec![
            TlsCertificateEntry {
                certificate: cert("wild"),
                server_names: vec![ServerNamePattern::WildcardSuffix(".example.com".into())],
            },
            TlsCertificateEntry {
                certificate: cert("exact"),
                server_names: vec![ServerNamePattern::Exact("a.example.com".into())],
            },
        ],
    };

    let selected = select_certificate(&config, Some("a.example.com")).unwrap();
    assert_eq!(selected.certificate.id.as_str(), "exact");
}

#[test]
fn wildcard_most_specific_longest_suffix_wins() {
    let config = TlsSelectionConfig {
        default_policy: DefaultCertificatePolicy::Reject,
        certificates: vec![
            TlsCertificateEntry {
                certificate: cert("less_specific"),
                server_names: vec![ServerNamePattern::WildcardSuffix(".example.com".into())],
            },
            TlsCertificateEntry {
                certificate: cert("more_specific"),
                server_names: vec![ServerNamePattern::WildcardSuffix(".sub.example.com".into())],
            },
        ],
    };

    let selected = select_certificate(&config, Some("a.sub.example.com")).unwrap();
    assert_eq!(selected.certificate.id.as_str(), "more_specific");
}

#[test]
fn wildcard_ties_resolve_by_stable_config_order() {
    let config = TlsSelectionConfig {
        default_policy: DefaultCertificatePolicy::Reject,
        certificates: vec![
            TlsCertificateEntry {
                certificate: cert("first"),
                server_names: vec![ServerNamePattern::WildcardSuffix(".example.com".into())],
            },
            TlsCertificateEntry {
                certificate: cert("second"),
                server_names: vec![ServerNamePattern::WildcardSuffix(".example.com".into())],
            },
        ],
    };

    let selected = select_certificate(&config, Some("a.example.com")).unwrap();
    assert_eq!(selected.certificate.id.as_str(), "first");
}

#[test]
fn absent_sni_uses_default_when_configured() {
    let config = TlsSelectionConfig {
        default_policy: DefaultCertificatePolicy::UseDefault(cert("default")),
        certificates: vec![],
    };

    let selected = select_certificate(&config, None).unwrap();
    assert_eq!(selected.certificate.id.as_str(), "default");
}

#[test]
fn absent_sni_rejects_when_no_default() {
    let config = TlsSelectionConfig {
        default_policy: DefaultCertificatePolicy::Reject,
        certificates: vec![],
    };

    let err = select_certificate(&config, None).unwrap_err();
    assert_eq!(
        err,
        CertificateSelectionError::NoDefaultCertificateConfigured
    );
}

#[test]
fn no_matching_sni_uses_default_when_configured() {
    let config = TlsSelectionConfig {
        default_policy: DefaultCertificatePolicy::UseDefault(cert("default")),
        certificates: vec![TlsCertificateEntry {
            certificate: cert("other"),
            server_names: vec![ServerNamePattern::Exact("b.example.com".into())],
        }],
    };

    let selected = select_certificate(&config, Some("a.example.com")).unwrap();
    assert_eq!(selected.certificate.id.as_str(), "default");
}

#[test]
fn no_matching_sni_rejects_when_no_default() {
    let config = TlsSelectionConfig {
        default_policy: DefaultCertificatePolicy::Reject,
        certificates: vec![TlsCertificateEntry {
            certificate: cert("other"),
            server_names: vec![ServerNamePattern::Exact("b.example.com".into())],
        }],
    };

    let err = select_certificate(&config, Some("a.example.com")).unwrap_err();
    assert_eq!(err, CertificateSelectionError::NoMatchingCertificate);
}

#[test]
fn blank_sni_is_treated_as_absent() {
    let config = TlsSelectionConfig {
        default_policy: DefaultCertificatePolicy::UseDefault(cert("default")),
        certificates: vec![],
    };

    let selected = select_certificate(&config, Some("   ")).unwrap();
    assert_eq!(selected.certificate.id.as_str(), "default");
}
