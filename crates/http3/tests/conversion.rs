use fingerprint_proxy_core::error::ErrorKind;
use fingerprint_proxy_http3::{
    reject_http3_http1x_mismatch, reject_http3_http2_mismatch, HTTP1_0_VERSION, HTTP1_1_VERSION,
    HTTP2_VERSION, HTTP3_VERSION,
};

#[test]
fn rejects_http3_http2_mismatch_both_directions() {
    let err = reject_http3_http2_mismatch(HTTP3_VERSION, HTTP2_VERSION)
        .expect_err("must reject HTTP/3 -> HTTP/2");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
    assert_eq!(
        err.message,
        "HTTP/3<->HTTP/2 mismatch is forbidden: source=HTTP/3 target=HTTP/2"
    );

    let err = reject_http3_http2_mismatch(HTTP2_VERSION, HTTP3_VERSION)
        .expect_err("must reject HTTP/2 -> HTTP/3");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
    assert_eq!(
        err.message,
        "HTTP/3<->HTTP/2 mismatch is forbidden: source=HTTP/2 target=HTTP/3"
    );
}

#[test]
fn rejects_http3_http1x_mismatch_both_directions() {
    let err = reject_http3_http1x_mismatch(HTTP3_VERSION, HTTP1_1_VERSION)
        .expect_err("must reject HTTP/3 -> HTTP/1.1");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
    assert_eq!(
        err.message,
        "HTTP/3<->HTTP/1.x mismatch is forbidden: source=HTTP/3 target=HTTP/1.1"
    );

    let err = reject_http3_http1x_mismatch(HTTP1_0_VERSION, HTTP3_VERSION)
        .expect_err("must reject HTTP/1.0 -> HTTP/3");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
    assert_eq!(
        err.message,
        "HTTP/3<->HTTP/1.x mismatch is forbidden: source=HTTP/1.0 target=HTTP/3"
    );
}

#[test]
fn accepts_non_mismatch_pairs() {
    reject_http3_http2_mismatch(HTTP3_VERSION, HTTP3_VERSION).expect("must allow HTTP/3 pair");
    reject_http3_http2_mismatch(HTTP2_VERSION, HTTP2_VERSION).expect("must allow HTTP/2 pair");
    reject_http3_http1x_mismatch(HTTP1_1_VERSION, HTTP1_0_VERSION)
        .expect("must allow HTTP/1.x pair");
}
