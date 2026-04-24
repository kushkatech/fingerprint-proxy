use fingerprint_proxy_core::request::HttpRequest;
use fingerprint_proxy_http1::{
    parse_websocket_upgrade_response_head, websocket_request_requires_takeover,
};

#[test]
fn websocket_takeover_detection_matches_upgrade_request() {
    let mut request = HttpRequest::new("GET", "/chat", "HTTP/1.1");
    request
        .headers
        .insert("Host".to_string(), "example.com".to_string());
    request
        .headers
        .insert("Upgrade".to_string(), "websocket".to_string());
    request
        .headers
        .insert("Connection".to_string(), "Upgrade".to_string());
    request
        .headers
        .insert("Sec-WebSocket-Version".to_string(), "13".to_string());
    request.headers.insert(
        "Sec-WebSocket-Key".to_string(),
        "dGhlIHNhbXBsZSBub25jZQ==".to_string(),
    );

    assert!(websocket_request_requires_takeover(&request));
}

#[test]
fn websocket_upgrade_response_head_returns_leftover_bytes() {
    let bytes = concat!(
        "HTTP/1.1 101\r\n",
        "Upgrade: websocket\r\n",
        "Connection: Upgrade\r\n",
        "Sec-WebSocket-Accept: x\r\n",
        "\r\n"
    )
    .as_bytes()
    .iter()
    .copied()
    .chain([0x81, 0x02, b'o', b'k'])
    .collect::<Vec<_>>();

    let parsed = parse_websocket_upgrade_response_head(&bytes, 8192)
        .expect("parse succeeds")
        .expect("response complete");
    assert_eq!(parsed.response.status, Some(101));
    assert_eq!(parsed.remaining, vec![0x81, 0x02, b'o', b'k']);
}
