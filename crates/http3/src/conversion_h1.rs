use crate::protocol::HTTP3_VERSION;
use fingerprint_proxy_core::error::{FpError, FpResult};

pub const HTTP1_1_VERSION: &str = "HTTP/1.1";
pub const HTTP1_0_VERSION: &str = "HTTP/1.0";

pub fn reject_http3_http1x_mismatch(source_version: &str, target_version: &str) -> FpResult<()> {
    let mismatch = (is_http3(source_version) && is_http1x(target_version))
        || (is_http1x(source_version) && is_http3(target_version));

    if mismatch {
        return Err(FpError::invalid_protocol_data(format!(
            "HTTP/3<->HTTP/1.x mismatch is forbidden: source={source_version} target={target_version}"
        )));
    }

    Ok(())
}

fn is_http3(version: &str) -> bool {
    version == HTTP3_VERSION
}

fn is_http1x(version: &str) -> bool {
    matches!(version, HTTP1_1_VERSION | HTTP1_0_VERSION)
}
