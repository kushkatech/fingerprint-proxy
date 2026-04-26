use crate::types::RuntimeStatsState;
use crate::PoolingCounters;
use crate::PoolingEvent;
use fingerprint_proxy_core::fingerprinting::FingerprintComputationResult;
use fingerprint_proxy_stats_api::aggregation::{AggregationInput, DataAvailability};
use fingerprint_proxy_stats_api::time_windows::EffectiveTimeWindow;
use std::sync::Mutex;

#[derive(Debug, Default)]
pub(crate) struct InMemoryStatsStorage {
    inner: Mutex<RuntimeStatsState>,
}

impl InMemoryStatsStorage {
    pub(crate) fn record_connection_opened(&self, at_unix: u64) {
        let mut guard = self.inner.lock().expect("runtime stats mutex poisoned");
        guard.system.record_connection_opened(at_unix);
    }

    pub(crate) fn record_connection_closed(&self) {
        let mut guard = self.inner.lock().expect("runtime stats mutex poisoned");
        guard.system.record_connection_closed();
    }

    pub(crate) fn record_request_processed(&self, at_unix: u64) {
        let mut guard = self.inner.lock().expect("runtime stats mutex poisoned");
        guard.system.record_request_processed(at_unix);
    }

    pub(crate) fn record_fingerprint_computation(
        &self,
        at_unix: u64,
        result: &FingerprintComputationResult,
    ) {
        let mut guard = self.inner.lock().expect("runtime stats mutex poisoned");
        guard.ja4t.record(at_unix, &result.fingerprints.ja4t);
        guard.ja4.record(at_unix, &result.fingerprints.ja4);
        guard.ja4one.record(at_unix, &result.fingerprints.ja4one);
    }

    pub(crate) fn record_upstream_error(&self, at_unix: u64) {
        let mut guard = self.inner.lock().expect("runtime stats mutex poisoned");
        guard.system.record_upstream_error(at_unix);
    }

    pub(crate) fn record_pooling_event(&self, at_unix: u64, event: PoolingEvent) {
        let mut guard = self.inner.lock().expect("runtime stats mutex poisoned");
        guard.pooling.record(at_unix, event);
    }

    pub(crate) fn record_configuration_update(&self, at_unix: u64) {
        let mut guard = self.inner.lock().expect("runtime stats mutex poisoned");
        guard.system.record_configuration_update_success(at_unix);
    }

    pub(crate) fn record_configuration_update_failure(&self, at_unix: u64) {
        let mut guard = self.inner.lock().expect("runtime stats mutex poisoned");
        guard.system.record_configuration_update_failure(at_unix);
    }

    pub(crate) fn snapshot(&self, window: &EffectiveTimeWindow) -> AggregationInput {
        let guard = self.inner.lock().expect("runtime stats mutex poisoned");
        let ja4t_snapshot = guard.ja4t.snapshot(window);
        let ja4_snapshot = guard.ja4.snapshot(window);
        let ja4one_snapshot = guard.ja4one.snapshot(window);
        let ja4t_availability = guard.ja4t.availability_snapshot(window);
        let ja4_availability = guard.ja4.availability_snapshot(window);
        let ja4one_availability = guard.ja4one.availability_snapshot(window);
        AggregationInput {
            system: guard.system.snapshot(window),
            ja4t: (
                ja4t_snapshot.0,
                ja4t_snapshot.1,
                DataAvailability {
                    ja4t_unavailable: ja4t_availability.ja4t_unavailable,
                    tls_data_unavailable: ja4t_availability.tls_data_unavailable,
                    protocol_data_unavailable: ja4t_availability.protocol_data_unavailable,
                },
            ),
            ja4: (
                ja4_snapshot.0,
                ja4_snapshot.1,
                DataAvailability {
                    ja4t_unavailable: ja4_availability.ja4t_unavailable,
                    tls_data_unavailable: ja4_availability.tls_data_unavailable,
                    protocol_data_unavailable: ja4_availability.protocol_data_unavailable,
                },
            ),
            ja4one: (
                ja4one_snapshot.0,
                ja4one_snapshot.1,
                DataAvailability {
                    ja4t_unavailable: ja4one_availability.ja4t_unavailable,
                    tls_data_unavailable: ja4one_availability.tls_data_unavailable,
                    protocol_data_unavailable: ja4one_availability.protocol_data_unavailable,
                },
            ),
        }
    }

    pub(crate) fn pooling_snapshot(&self, window: &EffectiveTimeWindow) -> PoolingCounters {
        let guard = self.inner.lock().expect("runtime stats mutex poisoned");
        guard.pooling.snapshot(window)
    }
}
