use crate::streams::ConnectionPreface;
use fingerprint_proxy_core::error::{FpError, FpResult};

pub const H2C_UPGRADE_TOKEN: &[u8] = b"h2c";

pub fn validate_h2c_prior_knowledge_preface(preface: &[u8]) -> FpResult<()> {
    if preface == ConnectionPreface::CLIENT_BYTES {
        return Ok(());
    }

    Err(FpError::invalid_protocol_data(
        "HTTP/2 cleartext requires the client connection preface (prior knowledge)",
    ))
}

pub fn reject_h2c_upgrade_transition() -> FpResult<()> {
    Err(FpError::invalid_protocol_data(
        "HTTP/2 cleartext upgrade-based transition is forbidden; use prior knowledge preface",
    ))
}
