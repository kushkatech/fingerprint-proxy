use fingerprint_proxy_core::request::{HttpRequest, HttpResponse};
use fingerprint_proxy_http2::{
    finalize_grpc_http2_response, grpc_http2_request_requires_transparent_forwarding,
    prepare_grpc_http2_request,
};

fn grpc_frame(message: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + message.len());
    out.push(0);
    out.extend_from_slice(&(message.len() as u32).to_be_bytes());
    out.extend_from_slice(message);
    out
}

#[test]
fn detects_grpc_http2_request_for_transparent_forwarding() {
    let mut request = HttpRequest::new("POST", "/svc.Method", "HTTP/2");
    request
        .headers
        .insert("content-type".to_string(), "application/grpc".to_string());

    assert!(grpc_http2_request_requires_transparent_forwarding(&request));
}

#[test]
fn prepare_grpc_http2_request_is_noop_for_non_grpc_request() {
    let request = HttpRequest::new("GET", "/", "HTTP/2");
    let prepared = prepare_grpc_http2_request(&request).expect("no-op");
    assert_eq!(prepared, request);
}

#[test]
fn finalize_grpc_http2_response_is_noop_for_non_grpc_request() {
    let request = HttpRequest::new("GET", "/", "HTTP/2");
    let response = HttpResponse {
        version: "HTTP/2".to_string(),
        status: Some(200),
        headers: Default::default(),
        trailers: Default::default(),
        body: b"ok".to_vec(),
    };

    let finalized = finalize_grpc_http2_response(&request, &response).expect("no-op");
    assert_eq!(finalized, response);
}

#[test]
fn grpc_http2_integration_requires_grpc_response_shape() {
    let mut request = HttpRequest::new("POST", "/svc.Method", "HTTP/2");
    request
        .headers
        .insert("content-type".to_string(), "application/grpc".to_string());
    request.body = grpc_frame(b"ping");

    let response = HttpResponse {
        version: "HTTP/2".to_string(),
        status: Some(200),
        headers: Default::default(),
        trailers: Default::default(),
        body: grpc_frame(b"pong"),
    };

    let err = finalize_grpc_http2_response(&request, &response).expect_err("must fail");
    assert_eq!(
        err.message,
        "gRPC upstream response must preserve application/grpc content-type"
    );
}
