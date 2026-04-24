use crate::config::{DefaultCertificatePolicy, ServerNamePattern, TlsSelectionConfig};
use fingerprint_proxy_core::error::{IssueSeverity, ValidationIssue, ValidationReport};

pub fn validate_tls_selection_config(config: &TlsSelectionConfig) -> ValidationReport {
    let mut report = ValidationReport::default();

    if config.certificates.is_empty() {
        match config.default_policy {
            DefaultCertificatePolicy::UseDefault(_) => {
                report.push(ValidationIssue::warning(
                    "tls.certificates",
                    "no SNI-based certificate entries are configured; only the default certificate can be selected",
                ));
            }
            DefaultCertificatePolicy::Reject => {
                report.push(ValidationIssue::error(
                    "tls.certificates",
                    "no certificates are configured and no default certificate is configured; all TLS handshakes would fail",
                ));
            }
        }
    }

    if matches!(config.default_policy, DefaultCertificatePolicy::Reject) {
        report.push(ValidationIssue {
            severity: IssueSeverity::Warning,
            path: "tls.default_policy".to_string(),
            message: "default certificate policy is Reject; SNI-absent connections will fail"
                .to_string(),
        });
    }

    for (idx, entry) in config.certificates.iter().enumerate() {
        let base = format!("tls.certificates[{idx}]");

        if entry.certificate.id.as_str().trim().is_empty() {
            report.push(ValidationIssue::error(
                format!("{base}.certificate.id"),
                "certificate id must be non-empty",
            ));
        }

        if entry.server_names.is_empty() {
            report.push(ValidationIssue::warning(
                format!("{base}.server_names"),
                "certificate entry has no server name patterns; it will never be selected by SNI",
            ));
        }

        for (pidx, pattern) in entry.server_names.iter().enumerate() {
            let pbase = format!("{base}.server_names[{pidx}]");
            match pattern {
                ServerNamePattern::Exact(name) if name.trim().is_empty() => {
                    report.push(ValidationIssue::error(
                        format!("{pbase}.exact"),
                        "exact name must be non-empty",
                    ))
                }
                ServerNamePattern::WildcardSuffix(suffix) if suffix.trim().is_empty() => report
                    .push(ValidationIssue::error(
                        format!("{pbase}.wildcard_suffix"),
                        "wildcard suffix must be non-empty",
                    )),
                _ => {}
            }
        }
    }

    report
}
