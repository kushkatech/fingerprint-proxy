use fingerprint_proxy_core::error::{FpError, FpResult};
use fingerprint_proxy_core::request::{HttpRequest, HttpResponse};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderField {
    pub name: String,
    pub value: String,
}

pub fn map_headers_to_request(fields: &[HeaderField]) -> FpResult<HttpRequest> {
    for field in fields {
        validate_header_name(&field.name)?;
    }

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
                    "HTTP/3 pseudo-headers must appear before regular headers",
                ));
            }

            match name {
                ":method" => {
                    if method.is_some() {
                        return Err(FpError::invalid_protocol_data(
                            "duplicate HTTP/3 pseudo-header: :method",
                        ));
                    }
                    if value.is_empty() {
                        return Err(FpError::invalid_protocol_data(
                            "HTTP/3 pseudo-header :method must be non-empty",
                        ));
                    }
                    method = Some(value);
                }
                ":scheme" => {
                    if scheme.is_some() {
                        return Err(FpError::invalid_protocol_data(
                            "duplicate HTTP/3 pseudo-header: :scheme",
                        ));
                    }
                    if value.is_empty() {
                        return Err(FpError::invalid_protocol_data(
                            "HTTP/3 pseudo-header :scheme must be non-empty",
                        ));
                    }
                    scheme = Some(value);
                }
                ":authority" => {
                    if authority.is_some() {
                        return Err(FpError::invalid_protocol_data(
                            "duplicate HTTP/3 pseudo-header: :authority",
                        ));
                    }
                    if value.is_empty() {
                        return Err(FpError::invalid_protocol_data(
                            "HTTP/3 pseudo-header :authority must be non-empty",
                        ));
                    }
                    authority = Some(value);
                }
                ":path" => {
                    if path.is_some() {
                        return Err(FpError::invalid_protocol_data(
                            "duplicate HTTP/3 pseudo-header: :path",
                        ));
                    }
                    if value.is_empty() {
                        return Err(FpError::invalid_protocol_data(
                            "HTTP/3 pseudo-header :path must be non-empty",
                        ));
                    }
                    path = Some(value);
                }
                _ => {
                    return Err(FpError::invalid_protocol_data(
                        "unsupported HTTP/3 pseudo-header",
                    ));
                }
            }

            continue;
        }

        saw_regular_header = true;

        if is_connection_specific_header(name) {
            return Err(FpError::invalid_protocol_data(
                "HTTP/3 connection-specific header is not allowed",
            ));
        }

        headers.insert(field.name.clone(), value);
    }

    let method = method.ok_or_else(|| {
        FpError::invalid_protocol_data("missing required HTTP/3 pseudo-header: :method")
    })?;
    let uri = path.ok_or_else(|| {
        FpError::invalid_protocol_data("missing required HTTP/3 pseudo-header: :path")
    })?;

    let mut req = HttpRequest::new(method, uri, "HTTP/3");
    req.headers = headers;

    let _ = scheme;
    let _ = authority;

    Ok(req)
}

pub fn map_headers_to_response(fields: &[HeaderField]) -> FpResult<HttpResponse> {
    for field in fields {
        validate_header_name(&field.name)?;
    }

    let mut status: Option<u16> = None;
    let mut saw_regular_header = false;
    let mut headers = std::collections::BTreeMap::<String, String>::new();

    for field in fields {
        let name = field.name.as_str();
        let value = field.value.clone();

        if name.starts_with(':') {
            if saw_regular_header {
                return Err(FpError::invalid_protocol_data(
                    "HTTP/3 pseudo-headers must appear before regular headers",
                ));
            }

            match name {
                ":status" => {
                    if status.is_some() {
                        return Err(FpError::invalid_protocol_data(
                            "duplicate HTTP/3 pseudo-header: :status",
                        ));
                    }
                    status = Some(parse_status(&value)?);
                }
                _ => {
                    return Err(FpError::invalid_protocol_data(
                        "unsupported HTTP/3 pseudo-header",
                    ));
                }
            }

            continue;
        }

        saw_regular_header = true;

        if is_connection_specific_header(name) {
            return Err(FpError::invalid_protocol_data(
                "HTTP/3 connection-specific header is not allowed",
            ));
        }

        headers.insert(field.name.clone(), value);
    }

    let status = status.ok_or_else(|| {
        FpError::invalid_protocol_data("missing required HTTP/3 pseudo-header: :status")
    })?;

    Ok(HttpResponse {
        version: "HTTP/3".to_string(),
        status: Some(status),
        headers,
        trailers: std::collections::BTreeMap::new(),
        body: Vec::new(),
    })
}

fn parse_status(value: &str) -> FpResult<u16> {
    if value.len() != 3 || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(FpError::invalid_protocol_data(
            "HTTP/3 :status must be a 3-digit integer",
        ));
    }
    let code: u16 = value
        .parse()
        .map_err(|_| FpError::invalid_protocol_data("HTTP/3 :status must be a valid integer"))?;
    if !(100..=599).contains(&code) {
        return Err(FpError::invalid_protocol_data(
            "HTTP/3 :status must be in range 100..=599",
        ));
    }
    Ok(code)
}

fn validate_header_name(name: &str) -> FpResult<()> {
    if name.is_empty() {
        return Err(FpError::invalid_protocol_data(
            "HTTP/3 header name must be non-empty",
        ));
    }
    if name.as_bytes().iter().any(|b| b.is_ascii_uppercase()) {
        return Err(FpError::invalid_protocol_data(
            "HTTP/3 header name must be lowercase",
        ));
    }
    Ok(())
}

fn is_connection_specific_header(name: &str) -> bool {
    matches!(
        name,
        "connection" | "proxy-connection" | "keep-alive" | "transfer-encoding" | "upgrade"
    )
}
