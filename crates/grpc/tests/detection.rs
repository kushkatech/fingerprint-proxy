use fingerprint_proxy_core::request::HttpRequest;
use fingerprint_proxy_grpc::{grpc_content_type_is_supported, is_grpc_request_over_http2};

#[test]
fn grpc_detection_requires_http2_and_grpc_content_type() {
    let mut request = HttpRequest::new("POST", "/svc/Method", "HTTP/2");
    request
        .headers
        .insert("content-type".to_string(), "application/grpc".to_string());

    assert!(is_grpc_request_over_http2(&request));
}

#[test]
fn grpc_detection_accepts_content_type_with_parameters() {
    let mut request = HttpRequest::new("POST", "/svc/Method", "HTTP/2");
    request.headers.insert(
        "content-type".to_string(),
        "application/grpc; charset=utf-8".to_string(),
    );

    assert!(is_grpc_request_over_http2(&request));
}

#[test]
fn grpc_detection_rejects_non_http2_or_non_grpc_content_type() {
    let mut non_http2 = HttpRequest::new("POST", "/svc/Method", "HTTP/1.1");
    non_http2
        .headers
        .insert("content-type".to_string(), "application/grpc".to_string());
    assert!(!is_grpc_request_over_http2(&non_http2));

    let mut wrong_content = HttpRequest::new("POST", "/svc/Method", "HTTP/2");
    wrong_content
        .headers
        .insert("content-type".to_string(), "application/json".to_string());
    assert!(!is_grpc_request_over_http2(&wrong_content));

    let missing_content = HttpRequest::new("POST", "/svc/Method", "HTTP/2");
    assert!(!is_grpc_request_over_http2(&missing_content));
}

#[test]
fn grpc_content_type_matching_is_case_insensitive_on_media_type() {
    assert!(grpc_content_type_is_supported("APPLICATION/GRPC"));
    assert!(!grpc_content_type_is_supported("application/grpc+proto"));
}
