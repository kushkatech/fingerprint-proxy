use crate::request::{
    find_headers_end, parse_header_line, validate_crlf_only, Http1ParseError, ParseOptions,
};
use fingerprint_proxy_core::request::HttpResponse;
use std::collections::BTreeMap;

pub fn parse_http1_response(
    input: &[u8],
    options: ParseOptions,
) -> Result<HttpResponse, Http1ParseError> {
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
    let status_line = lines.next().ok_or(Http1ParseError::InvalidStartLine)?;
    let status_line_str =
        std::str::from_utf8(status_line).map_err(|_| Http1ParseError::InvalidStartLine)?;
    let (version, status_code) = parse_status_line(status_line_str)?;

    let mut headers = BTreeMap::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let line_str = std::str::from_utf8(line).map_err(|_| Http1ParseError::InvalidHeaderLine)?;
        let (name, value) = parse_header_line(line_str)?;
        headers.insert(name, value);
    }

    Ok(HttpResponse {
        version: version.to_string(),
        status: Some(status_code),
        headers,
        trailers: BTreeMap::new(),
        body: Vec::new(),
    })
}

fn parse_status_line(line: &str) -> Result<(&str, u16), Http1ParseError> {
    let (version, rest) = line
        .split_once(' ')
        .ok_or(Http1ParseError::InvalidStartLine)?;
    if version != "HTTP/1.0" && version != "HTTP/1.1" {
        return Err(Http1ParseError::UnsupportedHttpVersion);
    }
    let status_str = rest
        .split(' ')
        .next()
        .ok_or(Http1ParseError::InvalidStartLine)?;
    if status_str.len() != 3 || !status_str.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Http1ParseError::InvalidStartLine);
    }
    let code: u16 = status_str
        .parse()
        .map_err(|_| Http1ParseError::InvalidStartLine)?;
    Ok((version, code))
}

fn strip_trailing_cr(line_with_lf: &[u8]) -> &[u8] {
    if line_with_lf.ends_with(b"\r") {
        &line_with_lf[..line_with_lf.len() - 1]
    } else {
        line_with_lf
    }
}
