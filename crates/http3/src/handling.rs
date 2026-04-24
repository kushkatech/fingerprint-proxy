use crate::frames::{Frame, FrameType};
use crate::headers::{map_headers_to_request, HeaderField};
use fingerprint_proxy_core::error::{FpError, FpResult};
use fingerprint_proxy_core::request::{HttpRequest, HttpResponse};
use std::collections::BTreeMap;

pub fn build_request_from_raw_parts<F>(
    raw_headers: &[u8],
    raw_trailers: Option<&[u8]>,
    body: Vec<u8>,
    decode_headers: F,
) -> FpResult<HttpRequest>
where
    F: Fn(&[u8]) -> FpResult<Vec<HeaderField>>,
{
    let fields = decode_headers(raw_headers)?;
    let mut request = map_headers_to_request(&fields)?;
    request.body = body;

    if let Some(raw) = raw_trailers {
        let trailer_fields = decode_headers(raw)?;
        request.trailers = validate_and_collect_trailers(&trailer_fields)?;
    }

    Ok(request)
}

pub fn encode_response_frames<HF, TF>(
    response: &HttpResponse,
    encode_response_headers: HF,
    encode_response_trailers: TF,
) -> FpResult<Vec<Frame>>
where
    HF: Fn(&HttpResponse) -> FpResult<Vec<u8>>,
    TF: Fn(&BTreeMap<String, String>) -> FpResult<Vec<u8>>,
{
    let headers = encode_response_headers(response)?;
    let has_body = !response.body.is_empty();
    let has_trailers = !response.trailers.is_empty();
    let mut out = Vec::with_capacity(match (has_body, has_trailers) {
        (false, false) => 1,
        (true, false) => 2,
        (false, true) => 2,
        (true, true) => 3,
    });
    out.push(Frame::new(FrameType::Headers, headers));

    if has_body {
        out.push(Frame::new(FrameType::Data, response.body.clone()));
    }

    if has_trailers {
        validate_response_trailers_map(&response.trailers)?;
        let trailer_bytes = encode_response_trailers(&response.trailers)?;
        out.push(Frame::new(FrameType::Headers, trailer_bytes));
    }

    Ok(out)
}

pub fn validate_and_collect_trailers(fields: &[HeaderField]) -> FpResult<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    for field in fields {
        validate_trailer_name(&field.name)?;
        out.insert(field.name.clone(), field.value.clone());
    }
    Ok(out)
}

pub fn validate_response_trailers_map(trailers: &BTreeMap<String, String>) -> FpResult<()> {
    for name in trailers.keys() {
        validate_trailer_name(name)?;
    }
    Ok(())
}

fn validate_trailer_name(name: &str) -> FpResult<()> {
    if name.is_empty() {
        return Err(FpError::invalid_protocol_data(
            "HTTP/3 trailer header name must be non-empty",
        ));
    }
    if name.as_bytes().iter().any(|b| b.is_ascii_uppercase()) {
        return Err(FpError::invalid_protocol_data(
            "HTTP/3 trailer header name must be lowercase",
        ));
    }
    if name.starts_with(':') {
        return Err(FpError::invalid_protocol_data(
            "HTTP/3 trailers must not contain pseudo-headers",
        ));
    }
    if is_connection_specific_header(name) {
        return Err(FpError::invalid_protocol_data(
            "HTTP/3 connection-specific header is not allowed",
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
