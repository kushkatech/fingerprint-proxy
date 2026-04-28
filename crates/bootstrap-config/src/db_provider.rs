use crate::config::BootstrapConfig;
use crate::provider::ConfigProvider;
use crate::version_retrieval::VersionedConfig;
use crate::versioning::ConfigVersionSelector;
use fingerprint_proxy_core::error::{FpError, FpResult};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbConfigProviderSettings {
    pub connection_uri: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DbConfigProvider {
    settings: Option<DbConfigProviderSettings>,
}

impl DbConfigProvider {
    pub fn unconfigured() -> Self {
        Self::default()
    }

    pub fn with_settings(settings: DbConfigProviderSettings) -> Self {
        Self {
            settings: Some(settings),
        }
    }
}

impl ConfigProvider for DbConfigProvider {
    fn load(&self) -> FpResult<BootstrapConfig> {
        match &self.settings {
            None => Err(FpError::invalid_configuration(
                "database config provider is unconfigured: missing database connection settings",
            )),
            Some(_) => Err(FpError::invalid_configuration(
                "database config provider is unsupported in this build; active runtime dynamic configuration supports only file providers",
            )),
        }
    }

    fn retrieve(
        &self,
        selector: ConfigVersionSelector,
    ) -> FpResult<VersionedConfig<BootstrapConfig>> {
        match selector {
            ConfigVersionSelector::Latest => Ok(VersionedConfig::Found(self.load()?)),
            ConfigVersionSelector::Specific(requested) => {
                Ok(VersionedConfig::SpecificVersionUnsupported {
                    requested,
                    provider: "database",
                })
            }
        }
    }
}
