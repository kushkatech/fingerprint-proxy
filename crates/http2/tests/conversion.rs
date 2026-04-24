use fingerprint_proxy_core::error::ErrorKind;
use fingerprint_proxy_http2::{
    reject_http2_http1x_mismatch, HTTP1_0_VERSION, HTTP1_1_VERSION, HTTP2_VERSION,
};

#[test]
fn accepts_matching_http2_versions() {
    reject_http2_http1x_mismatch(HTTP2_VERSION, HTTP2_VERSION)
        .expect("must allow HTTP/2 to HTTP/2");
}

#[test]
fn rejects_http2_to_http11_mismatch() {
    let err = reject_http2_http1x_mismatch(HTTP2_VERSION, HTTP1_1_VERSION)
        .expect_err("must reject HTTP/2 to HTTP/1.1 mismatch");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
    assert_eq!(
        err.message,
        "HTTP/2<->HTTP/1.x mismatch is forbidden: source=HTTP/2 target=HTTP/1.1"
    );
}

#[test]
fn rejects_http11_to_http2_mismatch() {
    let err = reject_http2_http1x_mismatch(HTTP1_1_VERSION, HTTP2_VERSION)
        .expect_err("must reject HTTP/1.1 to HTTP/2 mismatch");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
    assert_eq!(
        err.message,
        "HTTP/2<->HTTP/1.x mismatch is forbidden: source=HTTP/1.1 target=HTTP/2"
    );
}

#[test]
fn rejects_http2_to_http10_mismatch() {
    let err = reject_http2_http1x_mismatch(HTTP2_VERSION, HTTP1_0_VERSION)
        .expect_err("must reject HTTP/2 to HTTP/1.0 mismatch");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
    assert_eq!(
        err.message,
        "HTTP/2<->HTTP/1.x mismatch is forbidden: source=HTTP/2 target=HTTP/1.0"
    );
}

#[test]
fn accepts_non_http2_http1x_pair() {
    reject_http2_http1x_mismatch(HTTP1_1_VERSION, HTTP1_0_VERSION)
        .expect("must allow non-HTTP/2 pair");
}

#[test]
fn version_matching_is_case_sensitive() {
    reject_http2_http1x_mismatch("http/2", HTTP1_1_VERSION)
        .expect("must not infer version matching from non-canonical case");
}
