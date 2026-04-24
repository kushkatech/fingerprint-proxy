use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use fingerprint_proxy_core::error::{FpError, FpResult};
use fingerprint_proxy_core::request::{HttpRequest, HttpResponse};
use sha1::{Digest, Sha1};

use crate::upgrade::is_websocket_upgrade_request;

const WEBSOCKET_ACCEPT_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const WEBSOCKET_KEY_HEADER: &str = "sec-websocket-key";

pub fn complete_websocket_handshake(request: &HttpRequest) -> FpResult<HttpResponse> {
    if !is_websocket_upgrade_request(request) {
        return Err(FpError::invalid_protocol_data(
            "WebSocket handshake failed: request is not a valid upgrade request",
        ));
    }

    let key = request
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(WEBSOCKET_KEY_HEADER))
        .map(|(_, value)| value.trim())
        .ok_or_else(|| {
            FpError::invalid_protocol_data(
                "WebSocket handshake failed: missing Sec-WebSocket-Key header",
            )
        })?;

    let decoded_key = STANDARD.decode(key).map_err(|_| {
        FpError::invalid_protocol_data(
            "WebSocket handshake failed: invalid Sec-WebSocket-Key encoding",
        )
    })?;
    if decoded_key.len() != 16 {
        return Err(FpError::invalid_protocol_data(
            "WebSocket handshake failed: Sec-WebSocket-Key must decode to 16 bytes",
        ));
    }

    let mut response = HttpResponse {
        version: request.version.clone(),
        status: Some(101),
        ..HttpResponse::default()
    };
    response
        .headers
        .insert("Upgrade".to_string(), "websocket".to_string());
    response
        .headers
        .insert("Connection".to_string(), "Upgrade".to_string());
    response.headers.insert(
        "Sec-WebSocket-Accept".to_string(),
        websocket_accept_key(key),
    );

    Ok(response)
}

pub fn validate_websocket_handshake_response(
    request: &HttpRequest,
    response: &HttpResponse,
) -> FpResult<()> {
    if !is_websocket_upgrade_request(request) {
        return Err(FpError::invalid_protocol_data(
            "WebSocket handshake validation failed: request is not a valid upgrade request",
        ));
    }
    if response.status != Some(101) {
        return Err(FpError::invalid_protocol_data(
            "WebSocket handshake validation failed: upstream response is not 101",
        ));
    }

    let upgrade = response
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("upgrade"))
        .map(|(_, value)| value.as_str())
        .ok_or_else(|| {
            FpError::invalid_protocol_data(
                "WebSocket handshake validation failed: missing Upgrade header",
            )
        })?;
    if !upgrade.eq_ignore_ascii_case("websocket") {
        return Err(FpError::invalid_protocol_data(
            "WebSocket handshake validation failed: invalid Upgrade header",
        ));
    }

    let connection = response
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("connection"))
        .map(|(_, value)| value.as_str())
        .ok_or_else(|| {
            FpError::invalid_protocol_data(
                "WebSocket handshake validation failed: missing Connection header",
            )
        })?;
    if !connection
        .split(',')
        .any(|part| part.trim().eq_ignore_ascii_case("upgrade"))
    {
        return Err(FpError::invalid_protocol_data(
            "WebSocket handshake validation failed: invalid Connection header",
        ));
    }

    let key = request
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(WEBSOCKET_KEY_HEADER))
        .map(|(_, value)| value.trim())
        .ok_or_else(|| {
            FpError::invalid_protocol_data(
                "WebSocket handshake validation failed: missing Sec-WebSocket-Key header",
            )
        })?;
    let accept = response
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("sec-websocket-accept"))
        .map(|(_, value)| value.trim())
        .ok_or_else(|| {
            FpError::invalid_protocol_data(
                "WebSocket handshake validation failed: missing Sec-WebSocket-Accept header",
            )
        })?;
    if accept != websocket_accept_key(key) {
        return Err(FpError::invalid_protocol_data(
            "WebSocket handshake validation failed: invalid Sec-WebSocket-Accept header",
        ));
    }

    Ok(())
}

pub fn websocket_accept_key(client_key: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(client_key.as_bytes());
    hasher.update(WEBSOCKET_ACCEPT_GUID.as_bytes());
    STANDARD.encode(hasher.finalize())
}
