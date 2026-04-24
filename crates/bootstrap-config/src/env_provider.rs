use crate::config::BootstrapConfig;
use crate::provider::ConfigProvider;
use fingerprint_proxy_core::error::{FpError, FpResult};

#[derive(Debug, Clone, Copy)]
pub struct EnvConfigProvider;

impl ConfigProvider for EnvConfigProvider {
    fn load(&self) -> FpResult<BootstrapConfig> {
        Err(FpError::invalid_configuration(
            "environment config provider is not configured",
        ))
    }
}
