use fingerprint_proxy_core::error::{FpError, FpResult};

pub const HTTP3_VERSION: &str = "HTTP/3";
pub const HTTP3_ALPN: &str = "h3";

pub fn is_http3_alpn(alpn: &str) -> bool {
    alpn == HTTP3_ALPN
}

pub fn validate_http3_alpn(alpn: &str) -> FpResult<()> {
    if is_http3_alpn(alpn) {
        return Ok(());
    }

    Err(FpError::invalid_protocol_data(format!(
        "HTTP/3 ALPN mismatch: expected={HTTP3_ALPN} actual={alpn}"
    )))
}

pub fn is_client_initiated_bidirectional_stream(stream_id: u64) -> bool {
    stream_id & 0x03 == 0x00
}

pub fn validate_request_stream_id(stream_id: u64) -> FpResult<()> {
    if is_client_initiated_bidirectional_stream(stream_id) {
        return Ok(());
    }

    Err(FpError::invalid_protocol_data(format!(
        "HTTP/3 invalid request stream id: {stream_id}"
    )))
}
