use crate::headers::HeaderField;
use fingerprint_proxy_core::error::{FpError, FpResult};
use fingerprint_proxy_core::request::HttpResponse;

pub fn map_headers_to_response(fields: &[HeaderField]) -> FpResult<HttpResponse> {
    let mut status: Option<u16> = None;
    let mut saw_regular_header = false;
    let mut headers = std::collections::BTreeMap::<String, String>::new();

    for field in fields {
        let name = field.name.as_str();
        let value = field.value.clone();

        if name.starts_with(':') {
            if saw_regular_header {
                return Err(FpError::invalid_protocol_data(
                    "HTTP/2 pseudo-headers must appear before regular headers",
                ));
            }

            match name {
                ":status" => {
                    if status.is_some() {
                        return Err(FpError::invalid_protocol_data(
                            "duplicate HTTP/2 pseudo-header: :status",
                        ));
                    }
                    status = Some(parse_status(&value)?);
                }
                _ => {
                    return Err(FpError::invalid_protocol_data(
                        "unsupported HTTP/2 pseudo-header",
                    ));
                }
            }

            continue;
        }

        saw_regular_header = true;

        if is_connection_specific_header(name) {
            return Err(FpError::invalid_protocol_data(
                "HTTP/2 connection-specific header is not allowed",
            ));
        }

        headers.insert(field.name.clone(), value);
    }

    let status = status.ok_or_else(|| {
        FpError::invalid_protocol_data("missing required HTTP/2 pseudo-header: :status")
    })?;

    Ok(HttpResponse {
        version: "HTTP/2".to_string(),
        status: Some(status),
        headers,
        trailers: std::collections::BTreeMap::new(),
        body: Vec::new(),
    })
}

fn parse_status(value: &str) -> FpResult<u16> {
    if value.len() != 3 || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(FpError::invalid_protocol_data(
            "HTTP/2 :status must be a 3-digit integer",
        ));
    }
    let code: u16 = value
        .parse()
        .map_err(|_| FpError::invalid_protocol_data("HTTP/2 :status must be a valid integer"))?;
    if !(100..=599).contains(&code) {
        return Err(FpError::invalid_protocol_data(
            "HTTP/2 :status must be in range 100..=599",
        ));
    }
    Ok(code)
}

fn is_connection_specific_header(name: &str) -> bool {
    matches!(
        name,
        "connection" | "proxy-connection" | "keep-alive" | "transfer-encoding" | "upgrade"
    )
}
