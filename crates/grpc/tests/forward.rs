use fingerprint_proxy_core::request::{HttpRequest, HttpResponse};
use fingerprint_proxy_grpc::{
    finalize_grpc_forward_response, prepare_grpc_forward_request,
    response_looks_like_grpc_over_http2,
};

fn grpc_frame(message: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + message.len());
    out.push(0);
    out.extend_from_slice(&(message.len() as u32).to_be_bytes());
    out.extend_from_slice(message);
    out
}

#[test]
fn prepare_grpc_forward_request_requires_grpc_over_http2() {
    let mut request = HttpRequest::new("POST", "/svc.Method", "HTTP/1.1");
    request
        .headers
        .insert("content-type".to_string(), "application/grpc".to_string());

    let err = prepare_grpc_forward_request(&request).expect_err("must reject non-http2");
    assert_eq!(
        err.message,
        "gRPC transparent forwarding requires HTTP/2 with application/grpc content-type"
    );
}

#[test]
fn prepare_grpc_forward_request_preserves_grpc_headers_and_trailers() {
    let mut request = HttpRequest::new("POST", "/svc.Method", "HTTP/2");
    request
        .headers
        .insert("content-type".to_string(), "application/grpc".to_string());
    request
        .headers
        .insert("te".to_string(), "trailers".to_string());
    request
        .headers
        .insert("grpc-timeout".to_string(), "100m".to_string());
    request.body = grpc_frame(b"ping");
    request
        .trailers
        .insert("grpc-status-details-bin".to_string(), "AA==".to_string());

    let forwarded = prepare_grpc_forward_request(&request).expect("prepared request");
    assert_eq!(
        forwarded.headers.get("content-type").map(String::as_str),
        Some("application/grpc")
    );
    assert_eq!(
        forwarded.headers.get("grpc-timeout").map(String::as_str),
        Some("100m")
    );
    assert_eq!(
        forwarded
            .trailers
            .get("grpc-status-details-bin")
            .map(String::as_str),
        Some("AA==")
    );
    assert_eq!(forwarded.body, request.body);
}

#[test]
fn prepare_grpc_forward_request_does_not_require_complete_grpc_frame_buffer() {
    let mut request = HttpRequest::new("POST", "/svc.Method", "HTTP/2");
    request
        .headers
        .insert("content-type".to_string(), "application/grpc".to_string());
    request.body = vec![0, 0, 0];

    let forwarded = prepare_grpc_forward_request(&request).expect("transparent request");
    assert_eq!(forwarded.body, request.body);
}

#[test]
fn finalize_grpc_forward_response_requires_grpc_content_type() {
    let response = HttpResponse {
        version: "HTTP/2".to_string(),
        status: Some(200),
        headers: Default::default(),
        trailers: Default::default(),
        body: grpc_frame(b"pong"),
    };

    let err = finalize_grpc_forward_response(&response).expect_err("must reject non-grpc");
    assert_eq!(
        err.message,
        "gRPC upstream response must preserve application/grpc content-type"
    );
}

#[test]
fn finalize_grpc_forward_response_preserves_grpc_trailers() {
    let mut response = HttpResponse {
        version: "HTTP/2".to_string(),
        status: Some(200),
        headers: Default::default(),
        trailers: Default::default(),
        body: grpc_frame(b"pong"),
    };
    response.headers.insert(
        "content-type".to_string(),
        "application/grpc; charset=utf-8".to_string(),
    );
    response
        .headers
        .insert("grpc-encoding".to_string(), "identity".to_string());
    response
        .trailers
        .insert("grpc-status".to_string(), "0".to_string());
    response
        .trailers
        .insert("grpc-message".to_string(), String::new());

    let forwarded = finalize_grpc_forward_response(&response).expect("valid grpc response");
    assert!(response_looks_like_grpc_over_http2(&forwarded));
    assert_eq!(
        forwarded.headers.get("grpc-encoding").map(String::as_str),
        Some("identity")
    );
    assert_eq!(
        forwarded.trailers.get("grpc-status").map(String::as_str),
        Some("0")
    );
}

#[test]
fn finalize_grpc_forward_response_does_not_require_complete_grpc_frame_buffer() {
    let mut response = HttpResponse {
        version: "HTTP/2".to_string(),
        status: Some(200),
        headers: Default::default(),
        trailers: Default::default(),
        body: vec![0, 0, 0],
    };
    response
        .headers
        .insert("content-type".to_string(), "application/grpc".to_string());

    let forwarded = finalize_grpc_forward_response(&response).expect("transparent response");
    assert_eq!(forwarded.body, response.body);
}
