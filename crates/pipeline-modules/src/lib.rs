pub use fingerprint_proxy_core::error::{FpError, FpResult};

pub mod fingerprint_header;
pub mod forward;
pub mod network;

use fingerprint_proxy_pipeline::PipelineRegistry;

pub fn register_builtin_modules(registry: &mut PipelineRegistry) -> FpResult<()> {
    registry.register(fingerprint_header::MODULE_NAME, || {
        Box::new(fingerprint_header::FingerprintHeaderModule::new())
    })?;
    registry.register(network::module::MODULE_NAME, || {
        Box::new(network::module::NetworkClassificationModule::new())
    })?;
    registry.register(forward::MODULE_NAME, || {
        Box::new(forward::ForwardModule::new())
    })?;
    Ok(())
}
