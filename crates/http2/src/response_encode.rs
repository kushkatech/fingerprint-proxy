use fingerprint_proxy_core::error::{FpError, FpResult};
use fingerprint_proxy_core::request::HttpResponse;
use fingerprint_proxy_hpack::HeaderField as HpackField;

pub fn encode_http2_response_headers(
    encoder: &mut fingerprint_proxy_hpack::Encoder,
    resp: &HttpResponse,
) -> FpResult<Vec<u8>> {
    let status = resp.status.ok_or_else(|| {
        FpError::invalid_protocol_data("missing required HTTP/2 pseudo-header: :status")
    })?;
    if !(100..=599).contains(&status) {
        return Err(FpError::invalid_protocol_data(
            "HTTP/2 :status must be in range 100..=599",
        ));
    }

    let mut out = Vec::new();

    // Always emit mandatory :status first.
    out.extend_from_slice(&encoder.encode_literal_without_indexing(&HpackField {
        name: b":status".to_vec(),
        value: format!("{status:03}").into_bytes(),
    }));

    // Emit regular headers in deterministic order (BTreeMap iteration order).
    for (name, value) in resp.headers.iter() {
        if name.bytes().any(|b| b.is_ascii_uppercase()) {
            return Err(FpError::invalid_protocol_data(
                "HTTP/2 header name must be lowercase",
            ));
        }
        if is_connection_specific_header(name) {
            return Err(FpError::invalid_protocol_data(
                "HTTP/2 connection-specific header is not allowed",
            ));
        }

        out.extend_from_slice(&encoder.encode_literal_without_indexing(&HpackField {
            name: name.as_bytes().to_vec(),
            value: value.as_bytes().to_vec(),
        }));
    }

    Ok(out)
}

fn is_connection_specific_header(name: &str) -> bool {
    matches!(
        name,
        "connection" | "proxy-connection" | "keep-alive" | "transfer-encoding" | "upgrade"
    )
}
