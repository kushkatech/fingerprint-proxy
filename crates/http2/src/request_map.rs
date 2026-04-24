use crate::headers::HeaderField;
use fingerprint_proxy_core::error::{FpError, FpResult};
use fingerprint_proxy_core::request::HttpRequest;

pub fn map_headers_to_request(fields: &[HeaderField]) -> FpResult<HttpRequest> {
    let mut method: Option<String> = None;
    let mut scheme: Option<String> = None;
    let mut authority: Option<String> = None;
    let mut path: Option<String> = None;

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
                ":method" => {
                    if method.is_some() {
                        return Err(FpError::invalid_protocol_data(
                            "duplicate HTTP/2 pseudo-header: :method",
                        ));
                    }
                    if value.is_empty() {
                        return Err(FpError::invalid_protocol_data(
                            "HTTP/2 pseudo-header :method must be non-empty",
                        ));
                    }
                    method = Some(value);
                }
                ":scheme" => {
                    if scheme.is_some() {
                        return Err(FpError::invalid_protocol_data(
                            "duplicate HTTP/2 pseudo-header: :scheme",
                        ));
                    }
                    if value.is_empty() {
                        return Err(FpError::invalid_protocol_data(
                            "HTTP/2 pseudo-header :scheme must be non-empty",
                        ));
                    }
                    scheme = Some(value);
                }
                ":authority" => {
                    if authority.is_some() {
                        return Err(FpError::invalid_protocol_data(
                            "duplicate HTTP/2 pseudo-header: :authority",
                        ));
                    }
                    if value.is_empty() {
                        return Err(FpError::invalid_protocol_data(
                            "HTTP/2 pseudo-header :authority must be non-empty",
                        ));
                    }
                    authority = Some(value);
                }
                ":path" => {
                    if path.is_some() {
                        return Err(FpError::invalid_protocol_data(
                            "duplicate HTTP/2 pseudo-header: :path",
                        ));
                    }
                    if value.is_empty() {
                        return Err(FpError::invalid_protocol_data(
                            "HTTP/2 pseudo-header :path must be non-empty",
                        ));
                    }
                    path = Some(value);
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

        // Deterministic duplicate handling: BTreeMap insertion is last-write-wins.
        headers.insert(field.name.clone(), value);
    }

    let method = method.ok_or_else(|| {
        FpError::invalid_protocol_data("missing required HTTP/2 pseudo-header: :method")
    })?;
    let uri = path.ok_or_else(|| {
        FpError::invalid_protocol_data("missing required HTTP/2 pseudo-header: :path")
    })?;

    let mut req = HttpRequest::new(method, uri, "HTTP/2");
    req.headers = headers;

    let _ = scheme;
    let _ = authority;

    Ok(req)
}

fn is_connection_specific_header(name: &str) -> bool {
    matches!(
        name,
        "connection" | "proxy-connection" | "keep-alive" | "transfer-encoding" | "upgrade"
    )
}
