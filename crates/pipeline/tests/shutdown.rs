use fingerprint_proxy_core::error::ErrorKind;
use fingerprint_proxy_pipeline::PipelineShutdownCoordinator;
use std::time::Duration;

#[test]
fn tracks_in_flight_requests_and_drops_to_zero_on_finish() {
    let coordinator = PipelineShutdownCoordinator::new();

    let permit = coordinator
        .begin_in_flight_request()
        .expect("first request permit");
    let state = coordinator.state().expect("state");
    assert_eq!(state.in_flight_requests, 1);
    assert!(state.accepting_new_requests);

    permit.finish();

    let state = coordinator.state().expect("state");
    assert_eq!(state.in_flight_requests, 0);
    assert!(state.accepting_new_requests);
}

#[test]
fn shutdown_rejects_new_in_flight_requests() {
    let coordinator = PipelineShutdownCoordinator::new();
    let _existing = coordinator
        .begin_in_flight_request()
        .expect("initial request permit");

    let snapshot = coordinator.request_shutdown().expect("request shutdown");
    assert_eq!(snapshot.in_flight_requests, 1);
    assert!(!snapshot.accepting_new_requests);

    let err = coordinator
        .begin_in_flight_request()
        .expect_err("must reject new requests while shutting down");
    assert_eq!(err.kind, ErrorKind::Internal);
    assert_eq!(
        err.message,
        "pipeline is shutting down: no new in-flight requests are accepted"
    );
}

#[test]
fn wait_for_in_flight_requests_times_out_when_request_is_stuck() {
    let coordinator = PipelineShutdownCoordinator::new();
    let _permit = coordinator
        .begin_in_flight_request()
        .expect("initial request permit");
    coordinator.request_shutdown().expect("request shutdown");

    let err = coordinator
        .wait_for_in_flight_requests(Duration::from_millis(20))
        .expect_err("must time out while in-flight request remains");
    assert_eq!(err.kind, ErrorKind::Internal);
    assert_eq!(
        err.message,
        "graceful shutdown timed out while waiting for in-flight requests"
    );
}

#[test]
fn wait_for_in_flight_requests_returns_when_request_completes() {
    let coordinator = PipelineShutdownCoordinator::new();
    let permit = coordinator
        .begin_in_flight_request()
        .expect("initial request permit");
    coordinator.request_shutdown().expect("request shutdown");

    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(15));
        drop(permit);
    });

    coordinator
        .wait_for_in_flight_requests(Duration::from_millis(200))
        .expect("must drain in-flight requests");
    let state = coordinator.state().expect("state");
    assert_eq!(state.in_flight_requests, 0);
}
