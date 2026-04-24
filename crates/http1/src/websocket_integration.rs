use crate::{parse_http1_response, ParseOptions};
use fingerprint_proxy_core::error::{FpError, FpResult};
use fingerprint_proxy_core::request::{HttpRequest, HttpResponse};

pub struct ParsedWebSocketUpgradeResponse {
    pub response: HttpResponse,
    pub remaining: Vec<u8>,
}

pub fn websocket_request_requires_takeover(request: &HttpRequest) -> bool {
    fingerprint_proxy_websocket::is_websocket_upgrade_request(request)
}

pub fn parse_websocket_upgrade_response_head(
    input: &[u8],
    max_header_bytes: usize,
) -> FpResult<Option<ParsedWebSocketUpgradeResponse>> {
    let Some(header_end) = input.windows(4).position(|w| w == b"\r\n\r\n") else {
        if input.len() > max_header_bytes {
            return Err(FpError::invalid_protocol_data(
                "WebSocket upstream response headers too large",
            ));
        }
        return Ok(None);
    };

    let header_len = header_end + 4;
    if header_len > max_header_bytes {
        return Err(FpError::invalid_protocol_data(
            "WebSocket upstream response headers too large",
        ));
    }

    let response = parse_http1_response(
        &input[..header_len],
        ParseOptions {
            max_header_bytes: Some(max_header_bytes),
        },
    )
    .map_err(|_| FpError::invalid_protocol_data("WebSocket upstream response parse failed"))?;

    Ok(Some(ParsedWebSocketUpgradeResponse {
        response,
        remaining: input[header_len..].to_vec(),
    }))
}
