use crate::config::DomainConfig;
use crate::domain_provider::{load_domain_config_from_file, FP_DOMAIN_CONFIG_PATH_ENV_VAR};
use crate::version_retrieval::VersionedConfig;
use crate::versioning::ConfigVersionSelector;
use fingerprint_proxy_core::error::{FpError, FpResult};
use std::path::PathBuf;

pub trait DynamicDomainConfigProvider {
    fn load(&self) -> FpResult<DomainConfig>;

    fn retrieve(&self, selector: ConfigVersionSelector) -> FpResult<VersionedConfig<DomainConfig>> {
        match selector {
            ConfigVersionSelector::Latest => Ok(VersionedConfig::Found(self.load()?)),
            ConfigVersionSelector::Specific(requested) => {
                Ok(VersionedConfig::SpecificVersionUnsupported {
                    requested,
                    provider: "selected",
                })
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct FileDynamicDomainConfigProvider {
    path: PathBuf,
}

impl FileDynamicDomainConfigProvider {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn from_env_var(path_env_var: &str) -> FpResult<Self> {
        let path = std::env::var(path_env_var).map_err(|_| {
            FpError::invalid_configuration(format!("missing required env var {path_env_var}"))
        })?;
        Ok(Self::new(path))
    }
}

impl DynamicDomainConfigProvider for FileDynamicDomainConfigProvider {
    fn load(&self) -> FpResult<DomainConfig> {
        load_domain_config_from_file(&self.path)
    }

    fn retrieve(&self, selector: ConfigVersionSelector) -> FpResult<VersionedConfig<DomainConfig>> {
        match selector {
            ConfigVersionSelector::Latest => Ok(VersionedConfig::Found(self.load()?)),
            ConfigVersionSelector::Specific(requested) => {
                Ok(VersionedConfig::SpecificVersionUnsupported {
                    requested,
                    provider: "file",
                })
            }
        }
    }
}

pub fn load_dynamic_domain_config() -> FpResult<DomainConfig> {
    load_dynamic_domain_config_with_selector(ConfigVersionSelector::Latest)
}

pub fn load_dynamic_domain_config_with_selector(
    selector: ConfigVersionSelector,
) -> FpResult<DomainConfig> {
    match retrieve_dynamic_domain_config(selector)? {
        VersionedConfig::Found(config) => Ok(config),
        VersionedConfig::SpecificVersionUnsupported {
            requested,
            provider,
        } => Err(FpError::invalid_configuration(format!(
            "specific dynamic domain config version retrieval is unsupported by {provider} provider: {requested}"
        ))),
        VersionedConfig::SpecificVersionNotFound { requested } => Err(
            FpError::invalid_configuration(format!(
                "dynamic domain config version not found: {requested}"
            )),
        ),
    }
}

pub fn retrieve_dynamic_domain_config(
    selector: ConfigVersionSelector,
) -> FpResult<VersionedConfig<DomainConfig>> {
    if std::env::var_os(FP_DOMAIN_CONFIG_PATH_ENV_VAR).is_some() {
        return FileDynamicDomainConfigProvider::from_env_var(FP_DOMAIN_CONFIG_PATH_ENV_VAR)?
            .retrieve(selector);
    }

    Err(FpError::invalid_configuration(format!(
        "missing required env var {FP_DOMAIN_CONFIG_PATH_ENV_VAR}"
    )))
}
