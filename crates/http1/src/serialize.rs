use crate::request::{is_ascii_token, Http1ParseError};
use fingerprint_proxy_core::request::{HttpRequest, HttpResponse};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Http1SerializeError {
    InvalidStartLine,
    InvalidHeaderName,
    InvalidHeaderValue,
    MissingStatus,
}

pub fn serialize_http1_request(request: &HttpRequest) -> Result<Vec<u8>, Http1SerializeError> {
    if request.method.is_empty()
        || request.uri.is_empty()
        || request.version.is_empty()
        || request.method.contains(['\r', '\n', ' '])
        || request.uri.contains(['\r', '\n', ' '])
        || request.version.contains(['\r', '\n', ' '])
    {
        return Err(Http1SerializeError::InvalidStartLine);
    }

    let mut out = Vec::new();
    out.extend_from_slice(request.method.as_bytes());
    out.push(b' ');
    out.extend_from_slice(request.uri.as_bytes());
    out.push(b' ');
    out.extend_from_slice(request.version.as_bytes());
    out.extend_from_slice(b"\r\n");

    for (name, value) in &request.headers {
        write_header_line(&mut out, name, value)?;
    }
    out.extend_from_slice(b"\r\n");
    Ok(out)
}

pub fn serialize_http1_response(response: &HttpResponse) -> Result<Vec<u8>, Http1SerializeError> {
    let status = response.status.ok_or(Http1SerializeError::MissingStatus)?;
    let version = if response.version.is_empty() {
        "HTTP/1.1"
    } else {
        response.version.as_str()
    };
    if version != "HTTP/1.0" && version != "HTTP/1.1" {
        return Err(Http1SerializeError::InvalidStartLine);
    }

    let mut out = Vec::new();
    out.extend_from_slice(version.as_bytes());
    out.push(b' ');
    out.extend_from_slice(status.to_string().as_bytes());
    out.extend_from_slice(b"\r\n");

    for (name, value) in &response.headers {
        write_header_line(&mut out, name, value)?;
    }
    out.extend_from_slice(b"\r\n");
    Ok(out)
}

fn write_header_line(
    out: &mut Vec<u8>,
    name: &str,
    value: &str,
) -> Result<(), Http1SerializeError> {
    let name = name.trim();
    if name.is_empty() || !is_ascii_token(name) || name.bytes().any(|b| b == b' ' || b == b'\t') {
        return Err(Http1SerializeError::InvalidHeaderName);
    }
    if value.as_bytes().iter().any(|b| *b == b'\r' || *b == b'\n') {
        return Err(Http1SerializeError::InvalidHeaderValue);
    }

    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(b": ");
    out.extend_from_slice(value.as_bytes());
    out.extend_from_slice(b"\r\n");
    Ok(())
}

impl From<Http1ParseError> for Http1SerializeError {
    fn from(parse: Http1ParseError) -> Self {
        match parse {
            Http1ParseError::InvalidHeaderName => Self::InvalidHeaderName,
            Http1ParseError::InvalidHeaderValue => Self::InvalidHeaderValue,
            _ => Self::InvalidStartLine,
        }
    }
}
