use fingerprint_proxy_core::request::HttpRequest;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ParseOptions {
    pub max_header_bytes: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Http1ParseError {
    InvalidLineEnding,
    HeaderTooLarge { limit: usize, actual: usize },
    UnexpectedEof,
    InvalidStartLine,
    UnsupportedHttpVersion,
    ObsoleteLineFolding,
    InvalidHeaderLine,
    InvalidHeaderName,
    InvalidHeaderValue,
}

pub fn parse_http1_request(
    input: &[u8],
    options: ParseOptions,
) -> Result<HttpRequest, Http1ParseError> {
    validate_crlf_only(input)?;

    let header_end = find_headers_end(input).ok_or(Http1ParseError::UnexpectedEof)?;
    let header_block_len = header_end + 4;
    if let Some(limit) = options.max_header_bytes {
        if header_block_len > limit {
            return Err(Http1ParseError::HeaderTooLarge {
                limit,
                actual: header_block_len,
            });
        }
    }

    let header_block = &input[..header_end];
    let mut lines = header_block.split(|b| *b == b'\n').map(strip_trailing_cr);
    let start_line = lines.next().ok_or(Http1ParseError::InvalidStartLine)?;
    let start_line_str =
        std::str::from_utf8(start_line).map_err(|_| Http1ParseError::InvalidStartLine)?;

    let (method, uri, version) = parse_request_line(start_line_str)?;

    let mut headers = BTreeMap::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let line_str = std::str::from_utf8(line).map_err(|_| Http1ParseError::InvalidHeaderLine)?;
        let (name, value) = parse_header_line(line_str)?;
        headers.insert(name, value);
    }

    Ok(HttpRequest {
        method,
        uri,
        version,
        headers,
        trailers: BTreeMap::new(),
        body: Vec::new(),
    })
}

fn parse_request_line(line: &str) -> Result<(String, String, String), Http1ParseError> {
    let mut parts = line.split(' ');
    let method = parts.next().ok_or(Http1ParseError::InvalidStartLine)?;
    let uri = parts.next().ok_or(Http1ParseError::InvalidStartLine)?;
    let version = parts.next().ok_or(Http1ParseError::InvalidStartLine)?;
    if parts.next().is_some() {
        return Err(Http1ParseError::InvalidStartLine);
    }
    if method.is_empty() || uri.is_empty() || version.is_empty() {
        return Err(Http1ParseError::InvalidStartLine);
    }
    if version != "HTTP/1.0" && version != "HTTP/1.1" {
        return Err(Http1ParseError::UnsupportedHttpVersion);
    }
    Ok((method.to_string(), uri.to_string(), version.to_string()))
}

pub(crate) fn parse_header_line(line: &str) -> Result<(String, String), Http1ParseError> {
    if line.starts_with(' ') || line.starts_with('\t') {
        return Err(Http1ParseError::ObsoleteLineFolding);
    }
    let (name, raw_value) = line
        .split_once(':')
        .ok_or(Http1ParseError::InvalidHeaderLine)?;
    let name = name.trim();
    if name.is_empty() {
        return Err(Http1ParseError::InvalidHeaderName);
    }
    if !is_ascii_token(name) {
        return Err(Http1ParseError::InvalidHeaderName);
    }
    if name.bytes().any(|b| b == b' ' || b == b'\t') {
        return Err(Http1ParseError::InvalidHeaderName);
    }

    let value = raw_value.trim_matches([' ', '\t']);
    if value.as_bytes().iter().any(|b| *b == b'\r' || *b == b'\n') {
        return Err(Http1ParseError::InvalidHeaderValue);
    }

    Ok((name.to_string(), value.to_string()))
}

pub(crate) fn validate_crlf_only(input: &[u8]) -> Result<(), Http1ParseError> {
    let mut idx = 0usize;
    while idx < input.len() {
        match input[idx] {
            b'\n' => {
                if idx == 0 || input[idx - 1] != b'\r' {
                    return Err(Http1ParseError::InvalidLineEnding);
                }
            }
            b'\r' => {
                if idx + 1 >= input.len() || input[idx + 1] != b'\n' {
                    return Err(Http1ParseError::InvalidLineEnding);
                }
            }
            _ => {}
        }
        idx += 1;
    }
    Ok(())
}

pub(crate) fn find_headers_end(input: &[u8]) -> Option<usize> {
    input.windows(4).position(|w| w == b"\r\n\r\n")
}

fn strip_trailing_cr(line_with_lf: &[u8]) -> &[u8] {
    if line_with_lf.ends_with(b"\r") {
        &line_with_lf[..line_with_lf.len() - 1]
    } else {
        line_with_lf
    }
}

pub(crate) fn is_ascii_token(s: &str) -> bool {
    s.bytes().all(is_token_char)
}

fn is_token_char(b: u8) -> bool {
    matches!(b,
        b'a'..=b'z'
            | b'A'..=b'Z'
            | b'0'..=b'9'
            | b'!'
            | b'#'
            | b'$'
            | b'%'
            | b'&'
            | b'\''
            | b'*'
            | b'+'
            | b'-'
            | b'.'
            | b'^'
            | b'_'
            | b'`'
            | b'|'
            | b'~'
    )
}
