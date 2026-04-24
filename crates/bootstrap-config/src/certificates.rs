use crate::config::{BootstrapConfig, DefaultCertificatePolicy, ServerNamePattern};
use fingerprint_proxy_core::error::{FpError, FpResult, ValidationIssue, ValidationReport};
use fingerprint_proxy_tls_termination::config::{
    CertificateId, CertificateRef, DefaultCertificatePolicy as TlsDefaultCertificatePolicy,
    ServerNamePattern as TlsServerNamePattern, TlsCertificateEntry, TlsSelectionConfig,
};
use fingerprint_proxy_tls_termination::validation::validate_tls_selection_config;
use ring::rand::SystemRandom;
use ring::signature::{
    EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P384_SHA384_ASN1_SIGNING,
};
use rustls::crypto::ring::sign::any_supported_type;
use rustls::sign::CertifiedKey;
use std::collections::{BTreeMap, BTreeSet};
use std::io::BufReader;
use std::sync::Arc;
use x509_parser::prelude::FromDer;
use x509_parser::prelude::X509Certificate;

#[derive(Debug, Clone)]
pub struct LoadedTlsCertificates {
    pub selection: TlsSelectionConfig,
    pub keys_by_id: BTreeMap<CertificateId, Arc<CertifiedKey>>,
}

pub fn load_tls_certificates(bootstrap: &BootstrapConfig) -> FpResult<LoadedTlsCertificates> {
    let mut report = ValidationReport::default();
    let mut keys_by_id: BTreeMap<CertificateId, Arc<CertifiedKey>> = BTreeMap::new();
    let mut seen_ids: BTreeSet<String> = BTreeSet::new();

    for (idx, entry) in bootstrap.tls_certificates.iter().enumerate() {
        let base = format!("bootstrap.tls_certificates[{idx}]");

        if entry.id.trim().is_empty() {
            report.push(ValidationIssue::error(
                format!("{base}.id"),
                "certificate id must be non-empty",
            ));
            continue;
        }

        if !seen_ids.insert(entry.id.clone()) {
            report.push(ValidationIssue::error(
                format!("{base}.id"),
                "duplicate certificate id is not allowed",
            ));
            continue;
        }

        let cert_id = match CertificateId::new(entry.id.clone()) {
            Ok(id) => id,
            Err(_) => {
                report.push(ValidationIssue::error(
                    format!("{base}.id"),
                    "certificate id is invalid",
                ));
                continue;
            }
        };

        let cert_bytes = match std::fs::read(&entry.certificate_pem_path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                report.push(ValidationIssue::error(
                    format!("{base}.certificate_pem_path"),
                    format!(
                        "missing TLS certificate file: {}",
                        entry.certificate_pem_path
                    ),
                ));
                continue;
            }
            Err(_) => {
                report.push(ValidationIssue::error(
                    format!("{base}.certificate_pem_path"),
                    format!(
                        "failed to read TLS certificate file: {}",
                        entry.certificate_pem_path
                    ),
                ));
                continue;
            }
        };

        if cert_bytes.iter().all(|b| b.is_ascii_whitespace()) {
            report.push(ValidationIssue::error(
                format!("{base}.certificate_pem_path"),
                format!(
                    "empty TLS certificate chain: {}",
                    entry.certificate_pem_path
                ),
            ));
            continue;
        }

        let mut cert_reader = BufReader::new(cert_bytes.as_slice());
        let certs = match rustls_pemfile::certs(&mut cert_reader).collect::<Result<Vec<_>, _>>() {
            Ok(c) if c.is_empty() => {
                report.push(ValidationIssue::error(
                    format!("{base}.certificate_pem_path"),
                    format!(
                        "invalid TLS certificate PEM: {}",
                        entry.certificate_pem_path
                    ),
                ));
                continue;
            }
            Ok(c) => c,
            Err(_) => {
                report.push(ValidationIssue::error(
                    format!("{base}.certificate_pem_path"),
                    format!(
                        "invalid TLS certificate PEM: {}",
                        entry.certificate_pem_path
                    ),
                ));
                continue;
            }
        };

        let key_bytes = match std::fs::read(&entry.private_key_pem_path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                report.push(ValidationIssue::error(
                    format!("{base}.private_key_pem_path"),
                    format!(
                        "missing TLS private key file: {}",
                        entry.private_key_pem_path
                    ),
                ));
                continue;
            }
            Err(_) => {
                report.push(ValidationIssue::error(
                    format!("{base}.private_key_pem_path"),
                    format!(
                        "failed to read TLS private key file: {}",
                        entry.private_key_pem_path
                    ),
                ));
                continue;
            }
        };

        let mut key_reader = BufReader::new(key_bytes.as_slice());
        let key = match rustls_pemfile::private_key(&mut key_reader) {
            Ok(Some(k)) => k,
            Ok(None) => {
                report.push(ValidationIssue::error(
                    format!("{base}.private_key_pem_path"),
                    format!(
                        "missing TLS private key PEM: {}",
                        entry.private_key_pem_path
                    ),
                ));
                continue;
            }
            Err(_) => {
                report.push(ValidationIssue::error(
                    format!("{base}.private_key_pem_path"),
                    format!(
                        "invalid TLS private key PEM: {}",
                        entry.private_key_pem_path
                    ),
                ));
                continue;
            }
        };

        if !private_key_matches_leaf_cert_public_key(&certs[0], &key) {
            report.push(ValidationIssue::error(
                base.to_string(),
                format!(
                    "TLS private key does not match certificate: cert={} key={}",
                    entry.certificate_pem_path, entry.private_key_pem_path
                ),
            ));
            continue;
        }

        let signing_key = match any_supported_type(&key) {
            Ok(k) => k,
            Err(_) => {
                report.push(ValidationIssue::error(
                    format!("{base}.private_key_pem_path"),
                    format!(
                        "unsupported TLS private key type: {}",
                        entry.private_key_pem_path
                    ),
                ));
                continue;
            }
        };

        keys_by_id.insert(cert_id, Arc::new(CertifiedKey::new(certs, signing_key)));
    }

    let selection = build_tls_selection_config(bootstrap, &mut report);

    if report.has_errors() {
        return Err(FpError::validation_failed(format!(
            "TLS certificate loading failed:\n{report}"
        )));
    }

    let selection = selection.ok_or_else(|| {
        FpError::validation_failed("TLS certificate loading failed:\n(no selection config)")
    })?;

    if let TlsDefaultCertificatePolicy::UseDefault(ref cert) = selection.default_policy {
        if !keys_by_id.contains_key(&cert.id) {
            return Err(FpError::invalid_configuration(format!(
                "missing TLS certificate material for default id: {}",
                cert.id.as_str()
            )));
        }
    }

    for entry in &selection.certificates {
        if !keys_by_id.contains_key(&entry.certificate.id) {
            return Err(FpError::invalid_configuration(format!(
                "missing TLS certificate material for id: {}",
                entry.certificate.id.as_str()
            )));
        }
    }

    let selection_report = validate_tls_selection_config(&selection);
    if selection_report.has_errors() {
        return Err(FpError::validation_failed(format!(
            "TLS selection config validation failed:\n{selection_report}"
        )));
    }

    Ok(LoadedTlsCertificates {
        selection,
        keys_by_id,
    })
}

fn build_tls_selection_config(
    bootstrap: &BootstrapConfig,
    report: &mut ValidationReport,
) -> Option<TlsSelectionConfig> {
    let default_policy = match &bootstrap.default_certificate_policy {
        DefaultCertificatePolicy::Reject => TlsDefaultCertificatePolicy::Reject,
        DefaultCertificatePolicy::UseDefault(r) => {
            let id = match CertificateId::new(r.id.clone()) {
                Ok(id) => id,
                Err(_) => {
                    report.push(ValidationIssue::error(
                        "bootstrap.default_certificate_policy",
                        "default certificate id is invalid",
                    ));
                    return None;
                }
            };
            TlsDefaultCertificatePolicy::UseDefault(CertificateRef { id })
        }
    };

    let certificates = bootstrap
        .tls_certificates
        .iter()
        .filter_map(|c| {
            let id = CertificateId::new(c.id.clone()).ok()?;
            Some(TlsCertificateEntry {
                certificate: CertificateRef { id },
                server_names: c
                    .server_names
                    .iter()
                    .map(|p| match p {
                        ServerNamePattern::Exact(v) => TlsServerNamePattern::Exact(v.clone()),
                        ServerNamePattern::WildcardSuffix(v) => {
                            TlsServerNamePattern::WildcardSuffix(v.clone())
                        }
                    })
                    .collect(),
            })
        })
        .collect();

    Some(TlsSelectionConfig {
        default_policy,
        certificates,
    })
}

fn private_key_matches_leaf_cert_public_key(
    leaf_cert: &rustls::pki_types::CertificateDer<'static>,
    key: &rustls::pki_types::PrivateKeyDer<'static>,
) -> bool {
    let Ok((_rem, cert)) = X509Certificate::from_der(leaf_cert.as_ref()) else {
        return false;
    };
    let cert_pub = cert
        .tbs_certificate
        .subject_pki
        .subject_public_key
        .data
        .as_ref();

    let rustls::pki_types::PrivateKeyDer::Pkcs8(pkcs8) = key else {
        // Deterministic mismatch detection is only implemented for PKCS#8 keys in this phase.
        return true;
    };

    let rng = SystemRandom::new();

    if let Ok(kp) = EcdsaKeyPair::from_pkcs8(
        &ECDSA_P256_SHA256_ASN1_SIGNING,
        pkcs8.secret_pkcs8_der(),
        &rng,
    ) {
        return kp.public_key().as_ref() == cert_pub;
    }
    if let Ok(kp) = EcdsaKeyPair::from_pkcs8(
        &ECDSA_P384_SHA384_ASN1_SIGNING,
        pkcs8.secret_pkcs8_der(),
        &rng,
    ) {
        return kp.public_key().as_ref() == cert_pub;
    }

    // Unknown key type; mismatch detection not available here.
    true
}
