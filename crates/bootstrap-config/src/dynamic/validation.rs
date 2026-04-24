use crate::config::DomainConfig;
use crate::validation::validate_domain_config;
use crate::version_retrieval::VersionedConfig;
use crate::versioning::ConfigRevisionId;
use fingerprint_proxy_core::error::{FpError, FpResult};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedDomainConfigCandidate {
    revision_id: ConfigRevisionId,
    config: DomainConfig,
}

impl ValidatedDomainConfigCandidate {
    pub fn revision_id(&self) -> &ConfigRevisionId {
        &self.revision_id
    }

    pub fn config(&self) -> &DomainConfig {
        &self.config
    }

    pub fn into_config(self) -> DomainConfig {
        self.config
    }
}

pub fn validate_candidate_domain_config(
    candidate: DomainConfig,
) -> FpResult<ValidatedDomainConfigCandidate> {
    let report = validate_domain_config(&candidate);
    if report.has_errors() {
        return Err(FpError::validation_failed(format!(
            "dynamic domain config candidate validation failed:\n{report}"
        )));
    }

    Ok(ValidatedDomainConfigCandidate {
        revision_id: candidate.revision_id(),
        config: candidate,
    })
}

pub fn validate_retrieved_candidate(
    retrieved: VersionedConfig<DomainConfig>,
) -> FpResult<VersionedConfig<ValidatedDomainConfigCandidate>> {
    match retrieved {
        VersionedConfig::Found(candidate) => Ok(VersionedConfig::Found(
            validate_candidate_domain_config(candidate)?,
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
