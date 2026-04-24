use fingerprint_proxy_core::error::{FpError, FpResult};

pub const HTTP2_VERSION: &str = "HTTP/2";
pub const HTTP1_1_VERSION: &str = "HTTP/1.1";
pub const HTTP1_0_VERSION: &str = "HTTP/1.0";

pub fn reject_http2_http1x_mismatch(source_version: &str, target_version: &str) -> FpResult<()> {
    let mismatch = (is_http2(source_version) && is_http1x(target_version))
        || (is_http1x(source_version) && is_http2(target_version));

    if mismatch {
        return Err(FpError::invalid_protocol_data(format!(
            "HTTP/2<->HTTP/1.x mismatch is forbidden: source={source_version} target={target_version}"
        )));
    }

    Ok(())
}

fn is_http2(version: &str) -> bool {
    version == HTTP2_VERSION
}

fn is_http1x(version: &str) -> bool {
    matches!(version, HTTP1_1_VERSION | HTTP1_0_VERSION)
}
