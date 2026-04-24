use fingerprint_proxy_core::request::{HttpRequest, HttpResponse};
use fingerprint_proxy_http1::request::{parse_http1_request, Http1ParseError, ParseOptions};
use fingerprint_proxy_http1::response::parse_http1_response;
use fingerprint_proxy_http1::serialize::{
    serialize_http1_request, serialize_http1_response, Http1SerializeError,
};
use std::collections::BTreeMap;

#[test]
fn request_round_trip_start_line_and_headers() {
    let mut req = HttpRequest::new("GET", "/path", "HTTP/1.1");
    req.headers
        .insert("Host".to_string(), "example.com".to_string());
    req.headers.insert("X-Test".to_string(), "abc".to_string());

    let bytes = serialize_http1_request(&req).unwrap();
    let parsed = parse_http1_request(&bytes, ParseOptions::default()).unwrap();

    assert_eq!(parsed.method, "GET");
    assert_eq!(parsed.uri, "/path");
    assert_eq!(parsed.version, "HTTP/1.1");
    assert_eq!(
        parsed.headers.get("Host").map(String::as_str),
        Some("example.com")
    );
    assert_eq!(
        parsed.headers.get("X-Test").map(String::as_str),
        Some("abc")
    );
}

#[test]
fn response_round_trip_status_and_headers() {
    let mut resp = HttpResponse {
        version: "HTTP/1.1".to_string(),
        status: Some(200),
        headers: BTreeMap::new(),
        trailers: BTreeMap::new(),
        body: Vec::new(),
    };
    resp.headers
        .insert("Content-Type".to_string(), "text/plain".to_string());

    let bytes = serialize_http1_response(&resp).unwrap();
    assert!(bytes.starts_with(b"HTTP/1.1 200\r\n"));
    let parsed = parse_http1_response(&bytes, ParseOptions::default()).unwrap();

    assert_eq!(parsed.status, Some(200));
    assert_eq!(
        parsed.headers.get("Content-Type").map(String::as_str),
        Some("text/plain")
    );
}

#[test]
fn serialize_rejects_http2_version_in_response() {
    let resp = HttpResponse {
        version: "HTTP/2".to_string(),
        status: Some(200),
        headers: BTreeMap::new(),
        trailers: BTreeMap::new(),
        body: Vec::new(),
    };
    let err = serialize_http1_response(&resp).unwrap_err();
    assert_eq!(err, Http1SerializeError::InvalidStartLine);
}

#[test]
fn rejects_header_folding_obs_fold() {
    let input = b"GET / HTTP/1.1\r\nX: a\r\n\tb\r\n\r\n";
    let err = parse_http1_request(input, ParseOptions::default()).unwrap_err();
    assert_eq!(err, Http1ParseError::ObsoleteLineFolding);
}

#[test]
fn rejects_lf_only_line_endings() {
    let input = b"GET / HTTP/1.1\nHost: example.com\n\n";
    let err = parse_http1_request(input, ParseOptions::default()).unwrap_err();
    assert_eq!(err, Http1ParseError::InvalidLineEnding);
}

#[test]
fn rejects_invalid_header_name_chars() {
    let input = b"GET / HTTP/1.1\r\nBad Name: x\r\n\r\n";
    let err = parse_http1_request(input, ParseOptions::default()).unwrap_err();
    assert_eq!(err, Http1ParseError::InvalidHeaderName);
}

#[test]
fn enforces_max_header_bytes_limit() {
    let input = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let options = ParseOptions {
        max_header_bytes: Some(10),
    };
    let err = parse_http1_request(input, options).unwrap_err();
    assert!(matches!(err, Http1ParseError::HeaderTooLarge { .. }));
}

#[test]
fn serialize_rejects_invalid_header_name() {
    let mut req = HttpRequest::new("GET", "/", "HTTP/1.1");
    req.headers.insert("Bad Name".to_string(), "x".to_string());
    let err = serialize_http1_request(&req).unwrap_err();
    assert_eq!(err, Http1SerializeError::InvalidHeaderName);
}
