use fingerprint_proxy_core::request::HttpRequest;
use fingerprint_proxy_websocket::is_websocket_upgrade_request;

fn base_request() -> HttpRequest {
    let mut request = HttpRequest::new("GET", "/socket", "HTTP/1.1");
    request
        .headers
        .insert("Host".to_string(), "example.test".to_string());
    request
        .headers
        .insert("Connection".to_string(), "keep-alive, Upgrade".to_string());
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
fn detects_valid_websocket_upgrade_request() {
    let request = base_request();
    assert!(is_websocket_upgrade_request(&request));
}

#[test]
fn rejects_missing_upgrade_token_in_connection_header() {
    let mut request = base_request();
    request
        .headers
        .insert("Connection".to_string(), "keep-alive".to_string());
    assert!(!is_websocket_upgrade_request(&request));
}

#[test]
fn rejects_wrong_http_version() {
    let mut request = base_request();
    request.version = "HTTP/2".to_string();
    assert!(!is_websocket_upgrade_request(&request));
}

#[test]
fn rejects_missing_key() {
    let mut request = base_request();
    request.headers.remove("Sec-WebSocket-Key");
    assert!(!is_websocket_upgrade_request(&request));
}
