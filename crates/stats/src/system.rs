mod active;
mod config_updates;
mod connections;
mod requests;
mod upstream_errors;

use crate::system::active::ActiveConnectionsGauge;
use crate::system::config_updates::ConfigurationUpdateStats;
use crate::system::connections::TotalConnectionsStats;
use crate::system::requests::RequestsProcessedStats;
use crate::system::upstream_errors::UpstreamErrorStats;
use fingerprint_proxy_stats_api::aggregation::SystemCounters;
use fingerprint_proxy_stats_api::time_windows::EffectiveTimeWindow;

#[derive(Debug, Default)]
pub(crate) struct SystemStats {
    total_connections: TotalConnectionsStats,
    active_connections: ActiveConnectionsGauge,
    requests_processed: RequestsProcessedStats,
    upstream_errors: UpstreamErrorStats,
    configuration_updates: ConfigurationUpdateStats,
}

impl SystemStats {
    pub(crate) fn record_connection_opened(&mut self, at_unix: u64) {
        self.total_connections.record_opened(at_unix);
        self.active_connections.record_opened();
    }

    pub(crate) fn record_connection_closed(&mut self) {
        self.active_connections.record_closed();
    }

    pub(crate) fn record_request_processed(&mut self, at_unix: u64) {
        self.requests_processed.record(at_unix);
    }

    pub(crate) fn record_upstream_error(&mut self, at_unix: u64) {
        self.upstream_errors.record(at_unix);
    }

    pub(crate) fn record_configuration_update_success(&mut self, at_unix: u64) {
        self.configuration_updates.record_success(at_unix);
    }

    pub(crate) fn record_configuration_update_failure(&mut self, at_unix: u64) {
        self.configuration_updates.record_failure(at_unix);
    }

    pub(crate) fn snapshot(&self, window: &EffectiveTimeWindow) -> SystemCounters {
        let cfg = self.configuration_updates.snapshot(window);
        SystemCounters {
            total_connections: self.total_connections.count_in_window(window),
            active_connections: self.active_connections.current(),
            requests_processed: self.requests_processed.count_in_window(window),
            upstream_errors: self.upstream_errors.count_in_window(window),
            configuration_updates: cfg.successful_updates,
            configuration_update_failures: cfg.failed_updates,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_snapshot_aggregates_specialized_components() {
        let mut stats = SystemStats::default();
        stats.record_connection_opened(10);
        stats.record_connection_opened(20);
        stats.record_connection_closed();
        stats.record_request_processed(20);
        stats.record_upstream_error(30);
        stats.record_configuration_update_success(40);
        stats.record_configuration_update_failure(50);

        let window = EffectiveTimeWindow {
            from: 15,
            to: 45,
            window_seconds: 30,
        };
        let snapshot = stats.snapshot(&window);
        assert_eq!(snapshot.total_connections, 1);
        assert_eq!(snapshot.active_connections, 1);
        assert_eq!(snapshot.requests_processed, 1);
        assert_eq!(snapshot.upstream_errors, 1);
        assert_eq!(snapshot.configuration_updates, 1);
        assert_eq!(snapshot.configuration_update_failures, 0);
    }
}
