use crate::config::{
    CertificateRef, DefaultCertificatePolicy, ServerNamePattern, TlsSelectionConfig,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectedCertificate {
    pub certificate: CertificateRef,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertificateSelectionError {
    NoDefaultCertificateConfigured,
    NoMatchingCertificate,
}

pub fn select_certificate(
    config: &TlsSelectionConfig,
    server_name_indication: Option<&str>,
) -> Result<SelectedCertificate, CertificateSelectionError> {
    let sni = server_name_indication.and_then(|server_name| {
        let trimmed = server_name.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    });

    if let Some(sni) = sni {
        if let Some(selected) = select_for_sni(config, sni) {
            return Ok(selected);
        }

        return match &config.default_policy {
            DefaultCertificatePolicy::UseDefault(cert) => Ok(SelectedCertificate {
                certificate: cert.clone(),
            }),
            DefaultCertificatePolicy::Reject => {
                Err(CertificateSelectionError::NoMatchingCertificate)
            }
        };
    }

    match &config.default_policy {
        DefaultCertificatePolicy::UseDefault(cert) => Ok(SelectedCertificate {
            certificate: cert.clone(),
        }),
        DefaultCertificatePolicy::Reject => {
            Err(CertificateSelectionError::NoDefaultCertificateConfigured)
        }
    }
}

fn select_for_sni(config: &TlsSelectionConfig, sni: &str) -> Option<SelectedCertificate> {
    // Spec §3.1:
    // 1) Exact > wildcard
    // 2) Wildcard: most specific (longest suffix)
    // 3) Tie-breaker: stable configuration order

    for entry in &config.certificates {
        if entry.server_names.iter().any(|p| matches_exact(p, sni)) {
            return Some(SelectedCertificate {
                certificate: entry.certificate.clone(),
            });
        }
    }

    let mut best: Option<(usize, usize)> = None;
    for (idx, entry) in config.certificates.iter().enumerate() {
        for pattern in &entry.server_names {
            if let Some(len) = wildcard_suffix_len(pattern, sni) {
                match best {
                    None => best = Some((idx, len)),
                    Some((best_idx, best_len)) => {
                        if len > best_len || (len == best_len && idx < best_idx) {
                            best = Some((idx, len));
                        }
                    }
                }
            }
        }
    }

    best.map(|(idx, _)| SelectedCertificate {
        certificate: config.certificates[idx].certificate.clone(),
    })
}

fn matches_exact(pattern: &ServerNamePattern, sni: &str) -> bool {
    match pattern {
        ServerNamePattern::Exact(name) => name == sni,
        ServerNamePattern::WildcardSuffix(_) => false,
    }
}

fn wildcard_suffix_len(pattern: &ServerNamePattern, sni: &str) -> Option<usize> {
    match pattern {
        ServerNamePattern::WildcardSuffix(suffix) => {
            if suffix.is_empty() {
                return None;
            }
            if sni.len() <= suffix.len() {
                return None;
            }
            if sni.ends_with(suffix) {
                Some(suffix.len())
            } else {
                None
            }
        }
        ServerNamePattern::Exact(_) => None,
    }
}
