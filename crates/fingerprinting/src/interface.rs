use crate::model::{FingerprintComputationRequest, FingerprintComputationResult};
use fingerprint_proxy_core::error::FpResult;

pub trait FingerprintingSubsystem: Send + Sync {
    fn compute(
        &self,
        request: &FingerprintComputationRequest,
    ) -> FpResult<FingerprintComputationResult>;
}
