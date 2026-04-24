mod common;

use fingerprint_proxy_core::error::ErrorKind;
use fingerprint_proxy_core::upstream_protocol::{
    ensure_protocol_compatible, select_upstream_protocol, select_upstream_protocol_for_client,
    validate_upstream_protocol_config, ClientAppProtocol, SelectionInput, UpstreamAppProtocol,
    DEFAULT_ALLOWED_UPSTREAM_APP_PROTOCOLS,
};

#[test]
fn defaults_to_http1_when_unspecified() {
    common::init();
    let input = SelectionInput {
        allowed_upstream_app_protocols: None,
    };
    let selected = select_upstream_protocol(&input).expect("select");
    assert_eq!(selected, UpstreamAppProtocol::Http1);
    assert_eq!(
        DEFAULT_ALLOWED_UPSTREAM_APP_PROTOCOLS[0],
        UpstreamAppProtocol::Http1
    );
}

#[test]
fn selects_first_protocol_in_config_order() {
    common::init();
    let allowed = [UpstreamAppProtocol::Http2, UpstreamAppProtocol::Http1];
    let input = SelectionInput {
        allowed_upstream_app_protocols: Some(&allowed),
    };
    let selected = select_upstream_protocol(&input).expect("select");
    assert_eq!(selected, UpstreamAppProtocol::Http2);
}

#[test]
fn empty_allowed_list_is_invalid_configuration() {
    common::init();
    let allowed: [UpstreamAppProtocol; 0] = [];
    let input = SelectionInput {
        allowed_upstream_app_protocols: Some(&allowed),
    };
    let err = select_upstream_protocol(&input).unwrap_err();
    assert_eq!(err.kind, ErrorKind::InvalidConfiguration);
}

#[test]
fn validation_accepts_none_and_rejects_empty_or_duplicates() {
    common::init();

    let report = validate_upstream_protocol_config(None);
    assert!(!report.has_errors());

    let empty: [UpstreamAppProtocol; 0] = [];
    let report = validate_upstream_protocol_config(Some(&empty));
    assert!(report.has_errors());

    let dup = [UpstreamAppProtocol::Http2, UpstreamAppProtocol::Http2];
    let report = validate_upstream_protocol_config(Some(&dup));
    assert!(report.has_errors());
}

#[test]
fn determinism_same_input_same_output() {
    common::init();
    let allowed = [UpstreamAppProtocol::Http1, UpstreamAppProtocol::Http3];
    let input = SelectionInput {
        allowed_upstream_app_protocols: Some(&allowed),
    };
    let a = select_upstream_protocol(&input).expect("select");
    let b = select_upstream_protocol(&input).expect("select");
    assert_eq!(a, b);
}

#[test]
fn protocol_compatibility_allows_matching_protocols() {
    common::init();
    ensure_protocol_compatible(ClientAppProtocol::Http1, UpstreamAppProtocol::Http1).expect("ok");
    ensure_protocol_compatible(ClientAppProtocol::Http2, UpstreamAppProtocol::Http2).expect("ok");
    ensure_protocol_compatible(ClientAppProtocol::Http3, UpstreamAppProtocol::Http3).expect("ok");
}

#[test]
fn protocol_compatibility_rejects_mismatches_with_stable_error() {
    common::init();
    let err = ensure_protocol_compatible(ClientAppProtocol::Http2, UpstreamAppProtocol::Http1)
        .expect_err("must fail");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
    assert_eq!(
        err.message,
        "protocol mismatch: client=Http2 upstream=Http1"
    );
}

#[test]
fn select_upstream_protocol_for_client_wraps_selection_with_mismatch_guard() {
    common::init();
    let input = SelectionInput {
        allowed_upstream_app_protocols: None,
    };

    let selected =
        select_upstream_protocol_for_client(ClientAppProtocol::Http1, &input).expect("ok");
    assert_eq!(selected, UpstreamAppProtocol::Http1);

    let err = select_upstream_protocol_for_client(ClientAppProtocol::Http2, &input)
        .expect_err("mismatch");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
}
