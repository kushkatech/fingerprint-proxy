use crate::versioning::ConfigRevisionId;
use fingerprint_proxy_core::error::{FpError, FpResult};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionedConfig<T> {
    Found(T),
    SpecificVersionUnsupported {
        requested: ConfigRevisionId,
        provider: &'static str,
    },
    SpecificVersionNotFound {
        requested: ConfigRevisionId,
    },
}

impl<T> VersionedConfig<T> {
    pub fn into_config(self) -> FpResult<T> {
        match self {
            VersionedConfig::Found(config) => Ok(config),
            VersionedConfig::SpecificVersionUnsupported {
                requested,
                provider,
            } => Err(FpError::invalid_configuration(format!(
                "specific bootstrap config version retrieval is unsupported by {provider} provider: {requested}"
            ))),
            VersionedConfig::SpecificVersionNotFound { requested } => Err(
                FpError::invalid_configuration(format!(
                    "bootstrap config version not found: {requested}"
                )),
            ),
        }
    }
}
