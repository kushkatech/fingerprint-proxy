use fingerprint_proxy_core::error::ErrorKind;
use fingerprint_proxy_core::request::HttpRequest;
use fingerprint_proxy_websocket::{complete_websocket_handshake, websocket_accept_key};

fn upgrade_request() -> HttpRequest {
    let mut request = HttpRequest::new("GET", "/socket", "HTTP/1.1");
    request
        .headers
        .insert("Connection".to_string(), "Upgrade".to_string());
    request
        .headers
        .insert("Upgrade".to_string(), "websocket".to_string());
    request
        .headers
        .insert("Sec-WebSocket-Version".to_string(), "13".to_string());
    request.headers.insert(
        "Sec-WebSocket-Key".to_string(),
        "dGhlIHNhbXBsZSBub25jZQ==".to_string(),
    );
    request
}

#[test]
fn completes_server_handshake_for_valid_request() {
    let response = complete_websocket_handshake(&upgrade_request()).expect("handshake succeeds");
    assert_eq!(response.version, "HTTP/1.1");
    assert_eq!(response.status, Some(101));
    assert_eq!(
        response.headers.get("Upgrade").map(String::as_str),
        Some("websocket")
    );
    assert_eq!(
        response.headers.get("Connection").map(String::as_str),
        Some("Upgrade")
    );
    assert_eq!(
        response
            .headers
            .get("Sec-WebSocket-Accept")
            .map(String::as_str),
        Some("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
    );
}

#[test]
fn rejects_non_upgrade_request() {
    let request = HttpRequest::new("POST", "/socket", "HTTP/1.1");
    let error = complete_websocket_handshake(&request).expect_err("request is rejected");
    assert_eq!(error.kind, ErrorKind::InvalidProtocolData);
}

#[test]
fn rejects_invalid_key_encoding() {
    let mut request = upgrade_request();
    request.headers.insert(
        "Sec-WebSocket-Key".to_string(),
        "***not-base64***".to_string(),
    );
    let error = complete_websocket_handshake(&request).expect_err("request is rejected");
    assert_eq!(error.kind, ErrorKind::InvalidProtocolData);
    assert!(error.message.contains("invalid Sec-WebSocket-Key encoding"));
}

#[test]
fn computes_accept_key_deterministically() {
    assert_eq!(
        websocket_accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
        "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
    );
}
