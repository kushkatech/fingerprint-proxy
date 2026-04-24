use fingerprint_proxy_core::error::ErrorKind;
use fingerprint_proxy_http2::{map_headers_to_request, HeaderField};

#[test]
fn maps_rfc7541_example_to_http_request() {
    // RFC 7541 Appendix C.3.1 (decoded fields)
    let fields = vec![
        HeaderField {
            name: ":method".to_string(),
            value: "GET".to_string(),
        },
        HeaderField {
            name: ":scheme".to_string(),
            value: "http".to_string(),
        },
        HeaderField {
            name: ":path".to_string(),
            value: "/".to_string(),
        },
        HeaderField {
            name: ":authority".to_string(),
            value: "www.example.com".to_string(),
        },
    ];

    let req = map_headers_to_request(&fields).expect("map");
    assert_eq!(req.method, "GET");
    assert_eq!(req.uri, "/");
    assert_eq!(req.version, "HTTP/2");
    assert!(req.headers.is_empty());
}

#[test]
fn missing_method_is_error() {
    let fields = vec![HeaderField {
        name: ":path".to_string(),
        value: "/".to_string(),
    }];

    let err = map_headers_to_request(&fields).expect_err("must error");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
}

#[test]
fn pseudo_header_after_regular_header_is_error() {
    let fields = vec![
        HeaderField {
            name: ":method".to_string(),
            value: "GET".to_string(),
        },
        HeaderField {
            name: "x-test".to_string(),
            value: "1".to_string(),
        },
        HeaderField {
            name: ":path".to_string(),
            value: "/".to_string(),
        },
    ];

    let err = map_headers_to_request(&fields).expect_err("must error");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
}

#[test]
fn duplicate_path_is_error() {
    let fields = vec![
        HeaderField {
            name: ":method".to_string(),
            value: "GET".to_string(),
        },
        HeaderField {
            name: ":path".to_string(),
            value: "/".to_string(),
        },
        HeaderField {
            name: ":path".to_string(),
            value: "/other".to_string(),
        },
    ];

    let err = map_headers_to_request(&fields).expect_err("must error");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
}

#[test]
fn connection_specific_header_is_rejected() {
    let fields = vec![
        HeaderField {
            name: ":method".to_string(),
            value: "GET".to_string(),
        },
        HeaderField {
            name: ":path".to_string(),
            value: "/".to_string(),
        },
        HeaderField {
            name: "connection".to_string(),
            value: "keep-alive".to_string(),
        },
    ];

    let err = map_headers_to_request(&fields).expect_err("must error");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
}
