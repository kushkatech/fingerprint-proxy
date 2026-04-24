use fingerprint_proxy_core::error::ErrorKind;
use fingerprint_proxy_http3::{
    is_client_initiated_bidirectional_stream, validate_http3_alpn, validate_request_stream_id,
};

#[test]
fn accepts_exact_h3_alpn() {
    validate_http3_alpn("h3").expect("must accept exact h3");
}

#[test]
fn rejects_non_h3_alpn_values() {
    let err = validate_http3_alpn("h2").expect_err("must reject h2");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
    assert_eq!(err.message, "HTTP/3 ALPN mismatch: expected=h3 actual=h2");

    let err = validate_http3_alpn("H3").expect_err("must reject non-canonical case");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
    assert_eq!(err.message, "HTTP/3 ALPN mismatch: expected=h3 actual=H3");
}

#[test]
fn request_stream_validation_matches_quic_client_bidi_rule() {
    assert!(is_client_initiated_bidirectional_stream(0));
    assert!(is_client_initiated_bidirectional_stream(4));
    assert!(!is_client_initiated_bidirectional_stream(1));
    assert!(!is_client_initiated_bidirectional_stream(2));
    assert!(!is_client_initiated_bidirectional_stream(3));

    validate_request_stream_id(0).expect("must accept stream 0");
    validate_request_stream_id(4).expect("must accept stream 4");
    let err = validate_request_stream_id(1).expect_err("must reject stream 1");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
    assert_eq!(err.message, "HTTP/3 invalid request stream id: 1");
}
