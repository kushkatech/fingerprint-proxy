use fingerprint_proxy_core::error::{FpError, FpResult};

pub const ALPN_H2: &[u8] = b"h2";

pub fn ensure_h2_alpn(protocols: &mut Vec<Vec<u8>>) {
    if protocols.iter().all(|p| p.as_slice() != ALPN_H2) {
        protocols.push(ALPN_H2.to_vec());
    }
}

pub fn validate_h2_tls_alpn(negotiated_alpn: Option<&[u8]>) -> FpResult<()> {
    match negotiated_alpn {
        Some(ALPN_H2) => Ok(()),
        Some(_) => Err(FpError::invalid_protocol_data(
            "HTTP/2 over TLS ALPN mismatch: expected h2",
        )),
        None => Err(FpError::invalid_protocol_data(
            "HTTP/2 over TLS requires negotiated ALPN",
        )),
    }
}
