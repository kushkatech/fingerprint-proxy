use fingerprint_proxy_core::fingerprint::{
    Fingerprint, FingerprintAvailability, FingerprintFailureReason, FingerprintKind, Fingerprints,
};
use fingerprint_proxy_core::fingerprinting::{
    FingerprintComputationMetadata, FingerprintComputationResult,
};
use fingerprint_proxy_stats::{PoolingEvent, RuntimeStatsRegistry};
use fingerprint_proxy_stats_api::time_windows::EffectiveTimeWindow;
use std::time::SystemTime;

#[test]
fn snapshot_counts_windowed_events_and_active_connections() {
    let registry = RuntimeStatsRegistry::new();

    registry.record_connection_opened(90);
    registry.record_connection_opened(120);
    registry.record_upstream_error(125);
    registry.record_request(130, &missing_result(SystemTime::UNIX_EPOCH));
    registry.record_connection_closed();

    let snapshot = registry.snapshot(&EffectiveTimeWindow {
        from: 100,
        to: 150,
        window_seconds: 50,
    });

    assert_eq!(snapshot.system.total_connections, 1);
    assert_eq!(snapshot.system.active_connections, 1);
    assert_eq!(snapshot.system.requests_processed, 1);
    assert_eq!(snapshot.system.upstream_errors, 1);
    assert_eq!(snapshot.ja4.0.attempts, 1);
    assert_eq!(snapshot.ja4.0.failures, 1);
    assert_eq!(snapshot.ja4.1.missing_data, 1);
}

#[test]
fn hot_counters_are_aggregated_by_second() {
    let registry = RuntimeStatsRegistry::new();
    let result = missing_result(SystemTime::UNIX_EPOCH);

    registry.record_connection_opened(200);
    registry.record_connection_opened(200);
    registry.record_request(200, &result);
    registry.record_request(200, &result);
    registry.record_request(200, &result);
    registry.record_upstream_error(200);

    let snapshot = registry.snapshot(&EffectiveTimeWindow {
        from: 200,
        to: 200,
        window_seconds: 1,
    });

    assert_eq!(snapshot.system.total_connections, 2);
    assert_eq!(snapshot.system.requests_processed, 3);
    assert_eq!(snapshot.system.upstream_errors, 1);
    assert_eq!(snapshot.ja4.0.attempts, 3);
    assert_eq!(snapshot.ja4.0.failures, 3);
    assert_eq!(snapshot.ja4.1.missing_data, 3);
}

#[test]
fn snapshot_is_stable_for_out_of_order_event_timestamps() {
    let registry = RuntimeStatsRegistry::new();
    let result = missing_result(SystemTime::UNIX_EPOCH);

    registry.record_request(300, &result);
    registry.record_request(100, &result);

    let snapshot = registry.snapshot(&EffectiveTimeWindow {
        from: 50,
        to: 150,
        window_seconds: 100,
    });

    assert_eq!(snapshot.system.requests_processed, 1);
    assert_eq!(snapshot.ja4.0.attempts, 1);
    assert_eq!(snapshot.ja4.0.failures, 1);
}

#[test]
fn fingerprint_failure_categories_map_to_expected_counters() {
    let registry = RuntimeStatsRegistry::new();

    registry.record_request(400, &mixed_failure_result(SystemTime::UNIX_EPOCH));

    let snapshot = registry.snapshot(&EffectiveTimeWindow {
        from: 400,
        to: 400,
        window_seconds: 1,
    });

    assert_eq!(snapshot.ja4t.0.attempts, 1);
    assert_eq!(snapshot.ja4t.0.failures, 1);
    assert_eq!(snapshot.ja4t.1.parsing_errors, 1);

    assert_eq!(snapshot.ja4.0.attempts, 1);
    assert_eq!(snapshot.ja4.0.partials, 1);
    assert_eq!(snapshot.ja4.1.timeouts, 1);

    assert_eq!(snapshot.ja4one.0.attempts, 1);
    assert_eq!(snapshot.ja4one.0.failures, 1);
    assert_eq!(snapshot.ja4one.1.computation_errors, 1);
}

#[test]
fn ja4t_availability_statistics_track_complete_partial_and_unavailable() {
    let registry = RuntimeStatsRegistry::new();

    registry.record_request(
        500,
        &result_with_ja4t_state(
            SystemTime::UNIX_EPOCH,
            FingerprintAvailability::Complete,
            None,
        ),
    );
    registry.record_request(
        501,
        &result_with_ja4t_state(
            SystemTime::UNIX_EPOCH,
            FingerprintAvailability::Partial,
            Some(FingerprintFailureReason::Timeout),
        ),
    );
    registry.record_request(
        502,
        &result_with_ja4t_state(
            SystemTime::UNIX_EPOCH,
            FingerprintAvailability::Unavailable,
            Some(FingerprintFailureReason::ParsingError),
        ),
    );

    let snapshot = registry.snapshot(&EffectiveTimeWindow {
        from: 500,
        to: 502,
        window_seconds: 2,
    });

    assert_eq!(snapshot.ja4t.0.attempts, 3);
    assert_eq!(snapshot.ja4t.0.successes, 1);
    assert_eq!(snapshot.ja4t.0.partials, 1);
    assert_eq!(snapshot.ja4t.0.failures, 1);
    assert_eq!(snapshot.ja4t.1.timeouts, 1);
    assert_eq!(snapshot.ja4t.1.parsing_errors, 1);
    assert_eq!(snapshot.ja4t.1.missing_data, 0);
    assert_eq!(snapshot.ja4t.1.computation_errors, 0);
}

#[test]
fn snapshot_exposes_data_availability_counters() {
    let registry = RuntimeStatsRegistry::new();
    registry.record_request(600, &missing_result(SystemTime::UNIX_EPOCH));

    let snapshot = registry.snapshot(&EffectiveTimeWindow {
        from: 600,
        to: 600,
        window_seconds: 1,
    });

    assert_eq!(snapshot.ja4t.2.ja4t_unavailable, 1);
    assert_eq!(snapshot.ja4t.2.tls_data_unavailable, 0);
    assert_eq!(snapshot.ja4t.2.protocol_data_unavailable, 0);

    assert_eq!(snapshot.ja4.2.ja4t_unavailable, 0);
    assert_eq!(snapshot.ja4.2.tls_data_unavailable, 1);
    assert_eq!(snapshot.ja4.2.protocol_data_unavailable, 0);

    assert_eq!(snapshot.ja4one.2.ja4t_unavailable, 0);
    assert_eq!(snapshot.ja4one.2.tls_data_unavailable, 0);
    assert_eq!(snapshot.ja4one.2.protocol_data_unavailable, 1);
}

#[test]
fn configuration_update_counters_are_windowed() {
    let registry = RuntimeStatsRegistry::new();

    registry.record_configuration_update(10);
    registry.record_configuration_update(20);
    registry.record_configuration_update_failure(20);
    registry.record_configuration_update_failure(30);

    let snapshot = registry.snapshot(&EffectiveTimeWindow {
        from: 15,
        to: 25,
        window_seconds: 10,
    });

    assert_eq!(snapshot.system.configuration_updates, 1);
    assert_eq!(snapshot.system.configuration_update_failures, 1);
}

#[test]
fn pooling_counters_are_windowed() {
    let registry = RuntimeStatsRegistry::new();

    registry.record_pooling_event(40, PoolingEvent::Http1AcquireMiss);
    registry.record_pooling_event(41, PoolingEvent::Http1AcquireHit);
    registry.record_pooling_event(41, PoolingEvent::Http1ReleasePooled);
    registry.record_pooling_event(42, PoolingEvent::Http2AcquireStreamMiss);
    registry.record_pooling_event(43, PoolingEvent::Http2AcquireStreamHit);
    registry.record_pooling_event(44, PoolingEvent::Http2IdleTimeoutEviction);

    let counters = registry.pooling_snapshot(&EffectiveTimeWindow {
        from: 41,
        to: 43,
        window_seconds: 2,
    });

    assert_eq!(counters.http1_acquire_misses, 0);
    assert_eq!(counters.http1_acquire_hits, 1);
    assert_eq!(counters.http1_releases_pooled, 1);
    assert_eq!(counters.http2_stream_acquire_misses, 1);
    assert_eq!(counters.http2_stream_acquire_hits, 1);
    assert_eq!(counters.http2_idle_timeout_evictions, 0);
}

fn missing_result(at: SystemTime) -> FingerprintComputationResult {
    let mk = |kind| Fingerprint {
        kind,
        availability: FingerprintAvailability::Unavailable,
        value: None,
        computed_at: Some(at),
        failure_reason: Some(FingerprintFailureReason::MissingRequiredData),
    };

    FingerprintComputationResult {
        fingerprints: Fingerprints {
            ja4t: mk(FingerprintKind::Ja4T),
            ja4: mk(FingerprintKind::Ja4),
            ja4one: mk(FingerprintKind::Ja4One),
        },
        metadata: FingerprintComputationMetadata {
            computed_at: at,
            ja4one_components: None,
        },
    }
}

fn mixed_failure_result(at: SystemTime) -> FingerprintComputationResult {
    FingerprintComputationResult {
        fingerprints: Fingerprints {
            ja4t: Fingerprint {
                kind: FingerprintKind::Ja4T,
                availability: FingerprintAvailability::Unavailable,
                value: None,
                computed_at: Some(at),
                failure_reason: Some(FingerprintFailureReason::ParsingError),
            },
            ja4: Fingerprint {
                kind: FingerprintKind::Ja4,
                availability: FingerprintAvailability::Partial,
                value: None,
                computed_at: Some(at),
                failure_reason: Some(FingerprintFailureReason::Timeout),
            },
            ja4one: Fingerprint {
                kind: FingerprintKind::Ja4One,
                availability: FingerprintAvailability::Unavailable,
                value: None,
                computed_at: Some(at),
                failure_reason: Some(FingerprintFailureReason::Other),
            },
        },
        metadata: FingerprintComputationMetadata {
            computed_at: at,
            ja4one_components: None,
        },
    }
}

fn result_with_ja4t_state(
    at: SystemTime,
    availability: FingerprintAvailability,
    failure_reason: Option<FingerprintFailureReason>,
) -> FingerprintComputationResult {
    let ja4t = Fingerprint {
        kind: FingerprintKind::Ja4T,
        availability,
        value: (availability != FingerprintAvailability::Unavailable).then(|| "ja4t".to_string()),
        computed_at: Some(at),
        failure_reason,
    };

    let unavailable = |kind| Fingerprint {
        kind,
        availability: FingerprintAvailability::Unavailable,
        value: None,
        computed_at: Some(at),
        failure_reason: Some(FingerprintFailureReason::MissingRequiredData),
    };

    FingerprintComputationResult {
        fingerprints: Fingerprints {
            ja4t,
            ja4: unavailable(FingerprintKind::Ja4),
            ja4one: unavailable(FingerprintKind::Ja4One),
        },
        metadata: FingerprintComputationMetadata {
            computed_at: at,
            ja4one_components: None,
        },
    }
}
