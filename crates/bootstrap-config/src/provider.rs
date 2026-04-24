use crate::config::BootstrapConfig;
use crate::env_provider::EnvConfigProvider;
use crate::file_provider::FileConfigProvider;
use crate::version_retrieval::VersionedConfig;
use crate::versioning::ConfigVersionSelector;
use fingerprint_proxy_core::error::{FpError, FpResult};

pub const FP_CONFIG_PATH_ENV_VAR: &str = "FP_CONFIG_PATH";

pub trait ConfigProvider {
    fn load(&self) -> FpResult<BootstrapConfig>;

    fn retrieve(
        &self,
        selector: ConfigVersionSelector,
    ) -> FpResult<VersionedConfig<BootstrapConfig>> {
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

pub fn load_bootstrap_config() -> FpResult<BootstrapConfig> {
    load_bootstrap_config_with_selector(ConfigVersionSelector::Latest)
}

pub fn load_bootstrap_config_with_selector(
    selector: ConfigVersionSelector,
) -> FpResult<BootstrapConfig> {
    retrieve_bootstrap_config(selector)?.into_config()
}

pub fn retrieve_bootstrap_config(
    selector: ConfigVersionSelector,
) -> FpResult<VersionedConfig<BootstrapConfig>> {
    if std::env::var_os(FP_CONFIG_PATH_ENV_VAR).is_some() {
        return FileConfigProvider::from_env_var(FP_CONFIG_PATH_ENV_VAR)?.retrieve(selector);
    }

    // NOTE: tasks/spec do not define an environment config schema yet, so we cannot select it here
    // without inventing new selection rules.
    let _ = EnvConfigProvider;
    Err(FpError::invalid_configuration(format!(
        "missing required env var {FP_CONFIG_PATH_ENV_VAR}"
    )))
}
