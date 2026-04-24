use fingerprint_proxy_core::error::ErrorKind;
use fingerprint_proxy_tls_termination::ListenerAcceptControl;

#[test]
fn listener_accept_control_accepts_by_default() {
    let control = ListenerAcceptControl::new();
    assert!(control.is_accepting_new_connections());
    assert!(control.ensure_accepting_new_connections().is_ok());
}

#[test]
fn listener_accept_control_stops_accepting_deterministically() {
    let control = ListenerAcceptControl::new();

    assert!(control.request_stop_accepting());
    assert!(!control.is_accepting_new_connections());
    assert!(!control.request_stop_accepting());

    let err = control
        .ensure_accepting_new_connections()
        .expect_err("must reject new connections");
    assert_eq!(err.kind, ErrorKind::Internal);
    assert_eq!(
        err.message,
        "listener is shutting down: not accepting new connections"
    );
}
