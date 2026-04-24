use crate::certificates::LoadedTlsCertificates;
use crate::dynamic::validation::ValidatedDomainConfigCandidate;
use crate::version_retrieval::VersionedConfig;
use fingerprint_proxy_core::error::{FpError, FpResult, ValidationIssue, ValidationReport};
use fingerprint_proxy_tls_termination::config::CertificateId;

pub fn validate_candidate_certificate_references(
    candidate: ValidatedDomainConfigCandidate,
    loaded_certs: &LoadedTlsCertificates,
) -> FpResult<ValidatedDomainConfigCandidate> {
    let mut report = ValidationReport::default();

    for (idx, vhost) in candidate.config().virtual_hosts.iter().enumerate() {
        let path = format!("domain.virtual_hosts[{idx}].tls.certificate.id");
        let configured_id = vhost.tls.certificate.id.clone();

        let cert_id = match CertificateId::new(configured_id.clone()) {
            Ok(cert_id) => cert_id,
            Err(_) => {
                report.push(ValidationIssue::error(
                    path,
                    "referenced TLS certificate id is invalid",
                ));
                continue;
            }
        };

        if !loaded_certs.keys_by_id.contains_key(&cert_id) {
            report.push(ValidationIssue::error(
                path,
                format!(
                    "referenced TLS certificate id `{}` is not loaded in bootstrap certificate material",
                    cert_id.as_str()
                ),
            ));
        }
    }

    if report.has_errors() {
        return Err(FpError::validation_failed(format!(
            "dynamic TLS certificate validation failed:\n{report}"
        )));
    }

    Ok(candidate)
}

pub fn validate_retrieved_candidate_certificate_references(
    retrieved: VersionedConfig<ValidatedDomainConfigCandidate>,
    loaded_certs: &LoadedTlsCertificates,
) -> FpResult<VersionedConfig<ValidatedDomainConfigCandidate>> {
    match retrieved {
        VersionedConfig::Found(candidate) => Ok(VersionedConfig::Found(
            validate_candidate_certificate_references(candidate, loaded_certs)?,
        )),
        VersionedConfig::SpecificVersionUnsupported {
            requested,
            provider,
        } => Ok(VersionedConfig::SpecificVersionUnsupported {
            requested,
            provider,
        }),
        VersionedConfig::SpecificVersionNotFound { requested } => {
            Ok(VersionedConfig::SpecificVersionNotFound { requested })
        }
    }
}
