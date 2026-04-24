use fingerprint_proxy_core::error::ErrorKind;
use fingerprint_proxy_http2::{
    reject_h2c_upgrade_transition, validate_h2c_prior_knowledge_preface, ConnectionPreface,
    H2C_UPGRADE_TOKEN,
};

#[test]
fn validate_h2c_prior_knowledge_preface_accepts_exact_preface() {
    validate_h2c_prior_knowledge_preface(ConnectionPreface::CLIENT_BYTES)
        .expect("must accept HTTP/2 prior-knowledge preface");
}

#[test]
fn validate_h2c_prior_knowledge_preface_rejects_non_preface_bytes() {
    let err = validate_h2c_prior_knowledge_preface(b"GET / HTTP/1.1\r\n\r\n")
        .expect_err("must reject non-h2c prior-knowledge start");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
    assert_eq!(
        err.message,
        "HTTP/2 cleartext requires the client connection preface (prior knowledge)"
    );
}

#[test]
fn reject_h2c_upgrade_transition_is_deterministic() {
    let err = reject_h2c_upgrade_transition().expect_err("must reject upgrade transition");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
    assert_eq!(
        err.message,
        "HTTP/2 cleartext upgrade-based transition is forbidden; use prior knowledge preface"
    );
}

#[test]
fn h2c_upgrade_token_is_lowercase_h2c() {
    assert_eq!(H2C_UPGRADE_TOKEN, b"h2c");
}
