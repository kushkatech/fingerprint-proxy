use crate::config::BootstrapConfig;
use crate::provider::ConfigProvider;
use crate::version_retrieval::VersionedConfig;
use crate::versioning::ConfigVersionSelector;
use fingerprint_proxy_core::error::{FpError, FpResult};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiConfigProviderSettings {
    pub endpoint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ApiConfigProvider {
    settings: Option<ApiConfigProviderSettings>,
}

impl ApiConfigProvider {
    pub fn unconfigured() -> Self {
        Self::default()
    }

    pub fn with_settings(settings: ApiConfigProviderSettings) -> Self {
        Self {
            settings: Some(settings),
        }
    }
}

impl ConfigProvider for ApiConfigProvider {
    fn load(&self) -> FpResult<BootstrapConfig> {
        match &self.settings {
            None => Err(FpError::invalid_configuration(
                "api config provider is unconfigured: missing API endpoint settings",
            )),
            Some(_) => Err(FpError::invalid_configuration(
                "api config provider is unsupported in this build; active runtime dynamic configuration supports only file providers",
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
                    provider: "api",
                })
            }
        }
    }
}
