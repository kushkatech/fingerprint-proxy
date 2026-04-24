use fingerprint_proxy_bootstrap_config::config::BootstrapConfig;
use fingerprint_proxy_core::error::FpResult;

pub const FP_CONFIG_PATH_ENV_VAR: &str =
    fingerprint_proxy_bootstrap_config::provider::FP_CONFIG_PATH_ENV_VAR;

pub fn load_bootstrap_config() -> FpResult<BootstrapConfig> {
    fingerprint_proxy_bootstrap_config::provider::load_bootstrap_config()
}
