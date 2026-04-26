use fingerprint_proxy_core::fingerprinting::FingerprintComputationResult;
use fingerprint_proxy_stats::RuntimeStatsRegistry;
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct FingerprintingStatsIntegration {
    stats_registry: Arc<RuntimeStatsRegistry>,
}

impl FingerprintingStatsIntegration {
    pub fn new(stats_registry: Arc<RuntimeStatsRegistry>) -> Self {
        Self { stats_registry }
    }

    pub fn record_request_processed(&self, at_unix: u64) {
        self.stats_registry.record_request_processed(at_unix);
    }

    pub fn record_fingerprint_computation(
        &self,
        at_unix: u64,
        result: &FingerprintComputationResult,
    ) {
        self.stats_registry
            .record_fingerprint_computation(at_unix, result);
    }
}
