use crate::config::*;
use fingerprint_proxy_core::error::{IssueSeverity, ValidationIssue, ValidationReport};
use fingerprint_proxy_core::upstream_protocol::UpstreamAppProtocol;
use std::collections::BTreeSet;

pub fn validate_bootstrap_config(config: &BootstrapConfig) -> ValidationReport {
    let mut report = ValidationReport::default();

    match config.listener_acquisition_mode {
        ListenerAcquisitionMode::DirectBind => {
            if config.listeners.is_empty() {
                report.push(ValidationIssue::error(
                    "bootstrap.listeners",
                    "at least one listener must be configured in direct_bind mode",
                ));
            }
        }
        ListenerAcquisitionMode::InheritedSystemd => {
            if !config.listeners.is_empty() {
                report.push(ValidationIssue::error(
                    "bootstrap.listeners",
                    "listeners must be empty in inherited_systemd mode",
                ));
            }
            if config.enable_http3_quic_listeners {
                report.push(ValidationIssue::error(
                    "bootstrap.enable_http3_quic_listeners",
                    "HTTP/3 QUIC listeners are not supported in inherited_systemd mode",
                ));
            }
        }
    }

    if matches!(
        config.fingerprinting.ja4t.missing_tcp_metadata_policy,
        Ja4TMissingTcpMetadataPolicy::AllowUnavailable
    ) {
        report.push(ValidationIssue {
            severity: IssueSeverity::Warning,
            path: "bootstrap.fingerprinting.ja4t.missing_tcp_metadata_policy".to_string(),
            message: "JA4T missing TCP metadata policy allow_unavailable is intended only for testing/debugging; JA4T will be unavailable when saved-SYN capability cannot be acquired".to_string(),
        });
    }

    if config.stats_api.enabled {
        match &config.stats_api.network_policy {
            StatsApiNetworkPolicy::Disabled => {
                report.push(ValidationIssue {
                    severity: IssueSeverity::Warning,
                    path: "bootstrap.stats_api.network_policy".to_string(),
                    message:
                        "statistics API network restrictions are disabled; this is intended for development/testing only"
                            .to_string(),
                });
            }
            StatsApiNetworkPolicy::RequireAllowlist(cidrs) if cidrs.is_empty() => {
                report.push(ValidationIssue::error(
                    "bootstrap.stats_api.network_policy",
                    "allowlist must be non-empty when network restrictions are required",
                ));
            }
            StatsApiNetworkPolicy::RequireAllowlist(_) => {}
        }

        match &config.stats_api.auth_policy {
            StatsApiAuthPolicy::Disabled => {
                report.push(ValidationIssue {
                    severity: IssueSeverity::Warning,
                    path: "bootstrap.stats_api.auth_policy".to_string(),
                    message:
                        "statistics API authentication is disabled; this is intended for development/testing only"
                            .to_string(),
                });
            }
            StatsApiAuthPolicy::RequireCredentials(creds) if creds.is_empty() => {
                report.push(ValidationIssue::error(
                    "bootstrap.stats_api.auth_policy",
                    "credentials must be non-empty when authentication is required",
                ));
            }
            StatsApiAuthPolicy::RequireCredentials(_) => {}
        }

        if matches!(
            config.stats_api.network_policy,
            StatsApiNetworkPolicy::Disabled
        ) && matches!(config.stats_api.auth_policy, StatsApiAuthPolicy::Disabled)
        {
            report.push(ValidationIssue {
                severity: IssueSeverity::Warning,
                path: "bootstrap.stats_api".to_string(),
                message: "statistics API is enabled with both network restrictions and authentication disabled; this is intended for development/testing only".to_string(),
            });
        }
    }

    match &config.default_certificate_policy {
        DefaultCertificatePolicy::UseDefault(cert) if cert.id.trim().is_empty() => {
            report.push(ValidationIssue::error(
                "bootstrap.default_certificate_policy",
                "default certificate id must be non-empty",
            ));
        }
        _ => {}
    }

    let mut seen_cert_ids: BTreeSet<&str> = BTreeSet::new();
    for (idx, cert) in config.tls_certificates.iter().enumerate() {
        let base = format!("bootstrap.tls_certificates[{idx}]");

        if cert.id.trim().is_empty() {
            report.push(ValidationIssue::error(
                format!("{base}.id"),
                "certificate id must be non-empty",
            ));
        } else if !seen_cert_ids.insert(cert.id.as_str()) {
            report.push(ValidationIssue::error(
                format!("{base}.id"),
                "duplicate certificate id is not allowed",
            ));
        }

        if cert.certificate_pem_path.trim().is_empty() {
            report.push(ValidationIssue::error(
                format!("{base}.certificate_pem_path"),
                "certificate_pem_path must be non-empty",
            ));
        }
        validate_private_key_provider(&base, &cert.private_key_provider, &mut report);

        for (pidx, pat) in cert.server_names.iter().enumerate() {
            let pbase = format!("{base}.server_names[{pidx}]");
            match pat {
                ServerNamePattern::Exact(name) if name.trim().is_empty() => report.push(
                    ValidationIssue::error(format!("{pbase}.exact"), "SNI name must be non-empty"),
                ),
                ServerNamePattern::WildcardSuffix(suffix) if suffix.trim().is_empty() => report
                    .push(ValidationIssue::error(
                        format!("{pbase}.wildcard_suffix"),
                        "wildcard suffix must be non-empty",
                    )),
                _ => {}
            }
        }
    }

    if let DefaultCertificatePolicy::UseDefault(cert) = &config.default_certificate_policy {
        if !cert.id.trim().is_empty() {
            let exists = config
                .tls_certificates
                .iter()
                .any(|c| c.id.as_str() == cert.id.as_str());
            if !exists {
                report.push(ValidationIssue::error(
                    "bootstrap.default_certificate_policy",
                    "default certificate id must refer to a configured tls_certificates entry",
                ));
            }
        }
    }

    if let Some(provider) = &config.dynamic_provider {
        if provider.kind.trim().is_empty() {
            report.push(ValidationIssue::error(
                "bootstrap.dynamic_provider.kind",
                "provider kind must be non-empty when dynamic provider is configured",
            ));
        } else if !provider.is_supported_runtime_kind() {
            report.push(ValidationIssue::error(
                "bootstrap.dynamic_provider.kind",
                format!(
                    "unsupported dynamic provider kind `{}`; only `file` is supported for active runtime dynamic configuration",
                    provider.kind
                ),
            ));
        }

        if provider.polling_interval_seconds == 0 {
            report.push(ValidationIssue::error(
                "bootstrap.dynamic_provider.polling_interval_seconds",
                "dynamic polling interval must be greater than zero",
            ));
        }
    }

    report
}

fn validate_private_key_provider(
    base: &str,
    provider: &TlsPrivateKeyProviderConfig,
    report: &mut ValidationReport,
) {
    match provider {
        TlsPrivateKeyProviderConfig::File(file) => {
            if file.pem_path.trim().is_empty() {
                report.push(ValidationIssue::error(
                    format!("{base}.private_key_provider.pem_path"),
                    "file private key provider pem_path must be non-empty",
                ));
            }
        }
        TlsPrivateKeyProviderConfig::KnownUnsupported(kind) => {
            report.push(ValidationIssue::error(
                format!("{base}.private_key_provider.kind"),
                format!(
                    "private key provider kind `{}` is recognized but not supported in this build; only `file` is implemented",
                    kind.as_str()
                ),
            ));
        }
        TlsPrivateKeyProviderConfig::Unknown(provider) => {
            if provider.kind.trim().is_empty() {
                report.push(ValidationIssue::error(
                    format!("{base}.private_key_provider.kind"),
                    "private key provider kind must be non-empty",
                ));
            } else {
                report.push(ValidationIssue::error(
                    format!("{base}.private_key_provider.kind"),
                    format!(
                        "unknown private key provider kind `{}`; supported kind is `file`; recognized-but-unsupported kinds are `pkcs11`, `kms`, `tpm`",
                        provider.kind
                    ),
                ));
            }
        }
    }
}

pub fn validate_http3_quic_listener_policy(
    bootstrap: &BootstrapConfig,
    domain: &DomainConfig,
) -> ValidationReport {
    let mut report = ValidationReport::default();
    let has_http3_vhost = domain
        .virtual_hosts
        .iter()
        .any(|vhost| vhost.protocol.allow_http3);

    match (bootstrap.enable_http3_quic_listeners, has_http3_vhost) {
        (true, true) | (false, false) => {}
        (false, true) => {
            report.push(ValidationIssue::error(
                "bootstrap.enable_http3_quic_listeners",
                "one or more virtual hosts allow HTTP/3 but bootstrap HTTP/3 QUIC listeners are disabled",
            ));
        }
        (true, false) => {
            report.push(ValidationIssue::error(
                "bootstrap.enable_http3_quic_listeners",
                "bootstrap HTTP/3 QUIC listeners are enabled but no virtual host allows HTTP/3",
            ));
        }
    }

    report
}

pub fn validate_domain_config(config: &DomainConfig) -> ValidationReport {
    let mut report = ValidationReport::default();

    if config.version.as_str().trim().is_empty() {
        report.push(ValidationIssue::error(
            "domain.version",
            "domain configuration version identifier must be non-empty",
        ));
    }

    if config.fingerprint_headers.ja4t_header.trim().is_empty() {
        report.push(ValidationIssue::error(
            "domain.fingerprint_headers.ja4t_header",
            "header name must be non-empty",
        ));
    }
    if config.fingerprint_headers.ja4_header.trim().is_empty() {
        report.push(ValidationIssue::error(
            "domain.fingerprint_headers.ja4_header",
            "header name must be non-empty",
        ));
    }
    if config.fingerprint_headers.ja4one_header.trim().is_empty() {
        report.push(ValidationIssue::error(
            "domain.fingerprint_headers.ja4one_header",
            "header name must be non-empty",
        ));
    }

    let mut default_vhost_count = 0usize;
    for (idx, vhost) in config.virtual_hosts.iter().enumerate() {
        let base = format!("domain.virtual_hosts[{idx}]");

        if vhost.match_criteria.sni.is_empty() && vhost.match_criteria.destination.is_empty() {
            default_vhost_count += 1;
        }

        if vhost.tls.certificate.id.trim().is_empty() {
            report.push(ValidationIssue::error(
                format!("{base}.tls.certificate.id"),
                "certificate id must be non-empty",
            ));
        }

        if vhost.upstream.host.trim().is_empty() {
            report.push(ValidationIssue::error(
                format!("{base}.upstream.host"),
                "upstream host must be non-empty",
            ));
        }

        if vhost.upstream.port == 0 {
            report.push(ValidationIssue::warning(
                format!("{base}.upstream.port"),
                "upstream port is 0; this is usually unintended",
            ));
        }

        if let Some(allowed) = vhost.upstream.allowed_upstream_app_protocols.as_ref() {
            if allowed.is_empty() {
                report.push(ValidationIssue::error(
                    format!("{base}.upstream.allowed_upstream_app_protocols"),
                    "must be non-empty when specified",
                ));
            } else {
                let mut seen: BTreeSet<UpstreamAppProtocol> = BTreeSet::new();
                for (aidx, p) in allowed.iter().enumerate() {
                    if !seen.insert(*p) {
                        report.push(ValidationIssue::error(
                            format!("{base}.upstream.allowed_upstream_app_protocols[{aidx}]"),
                            "duplicate protocol is not allowed",
                        ));
                    }
                }
            }
        }

        if vhost.protocol.http2_server_push_policy == Http2ServerPushPolicy::Forward {
            report.push(ValidationIssue::error(
                format!("{base}.protocol.http2_server_push_policy"),
                "HTTP/2 server push forwarding is not supported; use suppress",
            ));
        }

        for (pidx, pat) in vhost.match_criteria.sni.iter().enumerate() {
            let pbase = format!("{base}.match_criteria.sni[{pidx}]");
            match pat {
                ServerNamePattern::Exact(name) if name.trim().is_empty() => report.push(
                    ValidationIssue::error(format!("{pbase}.exact"), "SNI name must be non-empty"),
                ),
                ServerNamePattern::WildcardSuffix(suffix) if suffix.trim().is_empty() => report
                    .push(ValidationIssue::error(
                        format!("{pbase}.wildcard_suffix"),
                        "wildcard suffix must be non-empty",
                    )),
                _ => {}
            }
        }

        if vhost.id == 0 {
            report.push(ValidationIssue::warning(
                format!("{base}.id"),
                "virtual host id is 0; ids are expected to be stable and unique",
            ));
        }
    }

    if default_vhost_count > 1 {
        report.push(ValidationIssue::error(
            "domain.virtual_hosts",
            "multiple default virtual hosts",
        ));
    }

    for (idx, rule) in config.client_classification_rules.iter().enumerate() {
        let base = format!("domain.client_classification_rules[{idx}]");
        if rule.name.trim().is_empty() {
            report.push(ValidationIssue::error(
                format!("{base}.name"),
                "classification rule name must be non-empty",
            ));
        }
        if rule.cidrs.is_empty() {
            report.push(ValidationIssue::error(
                format!("{base}.cidrs"),
                "classification rule must include at least one CIDR block",
            ));
        }
        for (cidx, cidr) in rule.cidrs.iter().enumerate() {
            let cbase = format!("{base}.cidrs[{cidx}]");
            let max = if cidr.addr.is_ipv4() { 32 } else { 128 };
            if cidr.prefix_len > max {
                report.push(ValidationIssue::error(
                    format!("{cbase}.prefix_len"),
                    format!("prefix length must be <= {max} for this address family"),
                ));
            }
        }
    }

    report
}
