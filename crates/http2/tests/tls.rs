use fingerprint_proxy_core::error::ErrorKind;
use fingerprint_proxy_http2::{ensure_h2_alpn, validate_h2_tls_alpn, ALPN_H2};

#[test]
fn ensure_h2_alpn_adds_h2_when_missing() {
    let mut protocols = vec![b"http/1.1".to_vec()];
    ensure_h2_alpn(&mut protocols);
    assert_eq!(protocols, vec![b"http/1.1".to_vec(), ALPN_H2.to_vec()]);
}

#[test]
fn ensure_h2_alpn_is_idempotent() {
    let mut protocols = vec![ALPN_H2.to_vec(), b"http/1.1".to_vec()];
    ensure_h2_alpn(&mut protocols);
    assert_eq!(protocols, vec![ALPN_H2.to_vec(), b"http/1.1".to_vec()]);
}

#[test]
fn validate_h2_tls_alpn_accepts_exact_h2() {
    validate_h2_tls_alpn(Some(ALPN_H2)).expect("must accept h2");
}

#[test]
fn validate_h2_tls_alpn_rejects_missing_alpn() {
    let err = validate_h2_tls_alpn(None).expect_err("must reject");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
    assert_eq!(err.message, "HTTP/2 over TLS requires negotiated ALPN");
}

#[test]
fn validate_h2_tls_alpn_rejects_mismatched_alpn() {
    let err = validate_h2_tls_alpn(Some(b"http/1.1")).expect_err("must reject");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
    assert_eq!(err.message, "HTTP/2 over TLS ALPN mismatch: expected h2");
}

#[test]
fn validate_h2_tls_alpn_is_case_sensitive() {
    let err = validate_h2_tls_alpn(Some(b"H2")).expect_err("must reject");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
    assert_eq!(err.message, "HTTP/2 over TLS ALPN mismatch: expected h2");
}
