use crate::storage::InMemoryStatsStorage;
use crate::{PoolingCounters, PoolingEvent};
use fingerprint_proxy_core::fingerprinting::FingerprintComputationResult;
use fingerprint_proxy_stats_api::aggregation::AggregationInput;
use fingerprint_proxy_stats_api::time_windows::EffectiveTimeWindow;
use std::sync::Arc;

pub trait StatsCollector: Send + Sync {
    fn record_connection_opened(&self, at_unix: u64);
    fn record_connection_closed(&self);
    fn record_request(&self, at_unix: u64, result: &FingerprintComputationResult);
    fn record_upstream_error(&self, at_unix: u64);
    fn record_pooling_event(&self, at_unix: u64, event: PoolingEvent);
    fn record_configuration_update(&self, at_unix: u64);
    fn record_configuration_update_failure(&self, at_unix: u64);
    fn snapshot(&self, window: &EffectiveTimeWindow) -> AggregationInput;
    fn pooling_snapshot(&self, window: &EffectiveTimeWindow) -> PoolingCounters;
}

#[derive(Debug, Default)]
pub struct RuntimeStatsRegistry {
    storage: InMemoryStatsStorage,
}

impl RuntimeStatsRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_connection_opened(&self, at_unix: u64) {
        self.storage.record_connection_opened(at_unix);
    }

    pub fn record_connection_closed(&self) {
        self.storage.record_connection_closed();
    }

    pub fn record_request(&self, at_unix: u64, result: &FingerprintComputationResult) {
        self.storage.record_request(at_unix, result);
    }

    pub fn record_upstream_error(&self, at_unix: u64) {
        self.storage.record_upstream_error(at_unix);
    }

    pub fn record_pooling_event(&self, at_unix: u64, event: PoolingEvent) {
        self.storage.record_pooling_event(at_unix, event);
    }

    pub fn record_configuration_update(&self, at_unix: u64) {
        self.storage.record_configuration_update(at_unix);
    }

    pub fn record_configuration_update_failure(&self, at_unix: u64) {
        self.storage.record_configuration_update_failure(at_unix);
    }

    pub fn snapshot(&self, window: &EffectiveTimeWindow) -> AggregationInput {
        self.storage.snapshot(window)
    }

    pub fn pooling_snapshot(&self, window: &EffectiveTimeWindow) -> PoolingCounters {
        self.storage.pooling_snapshot(window)
    }
}

impl StatsCollector for RuntimeStatsRegistry {
    fn record_connection_opened(&self, at_unix: u64) {
        self.storage.record_connection_opened(at_unix);
    }

    fn record_connection_closed(&self) {
        self.storage.record_connection_closed();
    }

    fn record_request(&self, at_unix: u64, result: &FingerprintComputationResult) {
        self.storage.record_request(at_unix, result);
    }

    fn record_upstream_error(&self, at_unix: u64) {
        self.storage.record_upstream_error(at_unix);
    }

    fn record_pooling_event(&self, at_unix: u64, event: PoolingEvent) {
        self.storage.record_pooling_event(at_unix, event);
    }

    fn record_configuration_update(&self, at_unix: u64) {
        self.storage.record_configuration_update(at_unix);
    }

    fn record_configuration_update_failure(&self, at_unix: u64) {
        self.storage.record_configuration_update_failure(at_unix);
    }

    fn snapshot(&self, window: &EffectiveTimeWindow) -> AggregationInput {
        self.storage.snapshot(window)
    }

    fn pooling_snapshot(&self, window: &EffectiveTimeWindow) -> PoolingCounters {
        self.storage.pooling_snapshot(window)
    }
}

pub struct ConnectionActivityGuard<'a> {
    registry: Arc<dyn StatsCollector>,
    _marker: std::marker::PhantomData<&'a RuntimeStatsRegistry>,
}

impl<'a> ConnectionActivityGuard<'a> {
    pub fn new(registry: Arc<RuntimeStatsRegistry>, at_unix: u64) -> Self {
        registry.record_connection_opened(at_unix);
        Self {
            registry,
            _marker: std::marker::PhantomData,
        }
    }
}

impl Drop for ConnectionActivityGuard<'_> {
    fn drop(&mut self) {
        self.registry.record_connection_closed();
    }
}
