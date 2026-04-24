use fingerprint_proxy_core::error::ErrorKind;
use fingerprint_proxy_http2::{map_headers_to_response, HeaderField};

#[test]
fn maps_valid_fields_to_http_response() {
    let fields = vec![
        HeaderField {
            name: ":status".to_string(),
            value: "200".to_string(),
        },
        HeaderField {
            name: "content-type".to_string(),
            value: "text/plain".to_string(),
        },
        HeaderField {
            name: "x-test".to_string(),
            value: "1".to_string(),
        },
    ];

    let resp = map_headers_to_response(&fields).expect("map");
    assert_eq!(resp.version, "HTTP/2");
    assert_eq!(resp.status, Some(200));
    assert_eq!(
        resp.headers.get("content-type").map(String::as_str),
        Some("text/plain")
    );
    assert_eq!(resp.headers.get("x-test").map(String::as_str), Some("1"));
    assert!(resp.body.is_empty());
}

#[test]
fn missing_status_is_error() {
    let fields = vec![HeaderField {
        name: "x-test".to_string(),
        value: "1".to_string(),
    }];

    let err = map_headers_to_response(&fields).expect_err("must error");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
}

#[test]
fn duplicate_status_is_error() {
    let fields = vec![
        HeaderField {
            name: ":status".to_string(),
            value: "200".to_string(),
        },
        HeaderField {
            name: ":status".to_string(),
            value: "204".to_string(),
        },
    ];

    let err = map_headers_to_response(&fields).expect_err("must error");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
}

#[test]
fn pseudo_header_after_regular_header_is_error() {
    let fields = vec![
        HeaderField {
            name: "x-test".to_string(),
            value: "1".to_string(),
        },
        HeaderField {
            name: ":status".to_string(),
            value: "200".to_string(),
        },
    ];

    let err = map_headers_to_response(&fields).expect_err("must error");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
}

#[test]
fn invalid_status_is_error() {
    for bad in ["99", "600", "abc"] {
        let fields = vec![HeaderField {
            name: ":status".to_string(),
            value: bad.to_string(),
        }];
        let err = map_headers_to_response(&fields).expect_err("must error");
        assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
    }
}

#[test]
fn connection_header_is_rejected() {
    let fields = vec![
        HeaderField {
            name: ":status".to_string(),
            value: "200".to_string(),
        },
        HeaderField {
            name: "connection".to_string(),
            value: "keep-alive".to_string(),
        },
    ];

    let err = map_headers_to_response(&fields).expect_err("must error");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
}
