use fingerprint_proxy_fingerprinting::model::{ConnectionTuple, TransportHint};
use fingerprint_proxy_fingerprinting::{
    compute_runtime_fingerprinting_result, FingerprintingStatsIntegration,
};
use fingerprint_proxy_stats::RuntimeStatsRegistry;
use fingerprint_proxy_stats_api::time_windows::EffectiveTimeWindow;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::SystemTime;

#[test]
fn record_request_fingerprints_preserves_runtime_counter_semantics() {
    let runtime_stats = Arc::new(RuntimeStatsRegistry::new());
    let integration = FingerprintingStatsIntegration::new(Arc::clone(&runtime_stats));
    let result = compute_runtime_fingerprinting_result(
        sample_connection_tuple(),
        None,
        SystemTime::UNIX_EPOCH,
    );

    integration.record_request_fingerprints(130, &result);

    let snapshot = runtime_stats.snapshot(&EffectiveTimeWindow {
        from: 100,
        to: 150,
        window_seconds: 50,
    });

    assert_eq!(snapshot.system.requests_processed, 1);
    assert_eq!(snapshot.ja4t.0.attempts, 1);
    assert_eq!(snapshot.ja4t.0.failures, 1);
    assert_eq!(snapshot.ja4t.1.missing_data, 1);
    assert_eq!(snapshot.ja4.0.attempts, 1);
    assert_eq!(snapshot.ja4.0.failures, 1);
    assert_eq!(snapshot.ja4.1.missing_data, 1);
    assert_eq!(snapshot.ja4one.0.attempts, 1);
    assert_eq!(snapshot.ja4one.0.failures, 1);
    assert_eq!(snapshot.ja4one.1.missing_data, 1);
}

fn sample_connection_tuple() -> ConnectionTuple {
    ConnectionTuple {
        source_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        source_port: 40123,
        destination_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
        destination_port: 443,
        transport: TransportHint::Tcp,
    }
}
