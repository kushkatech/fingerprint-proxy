use crate::protocol::HTTP3_VERSION;
use fingerprint_proxy_core::error::{FpError, FpResult};

pub const HTTP2_VERSION: &str = "HTTP/2";

pub fn reject_http3_http2_mismatch(source_version: &str, target_version: &str) -> FpResult<()> {
    let mismatch = (is_http3(source_version) && is_http2(target_version))
        || (is_http2(source_version) && is_http3(target_version));

    if mismatch {
        return Err(FpError::invalid_protocol_data(format!(
            "HTTP/3<->HTTP/2 mismatch is forbidden: source={source_version} target={target_version}"
        )));
    }

    Ok(())
}

fn is_http3(version: &str) -> bool {
    version == HTTP3_VERSION
}

fn is_http2(version: &str) -> bool {
    version == HTTP2_VERSION
}
