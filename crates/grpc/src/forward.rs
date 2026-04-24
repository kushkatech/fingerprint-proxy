use crate::detection::{grpc_content_type_is_supported, is_grpc_request_over_http2};
use crate::frames::parse_grpc_frames;
use crate::headers::{preserve_grpc_headers, preserve_grpc_trailers};
use fingerprint_proxy_core::error::{FpError, FpResult};
use fingerprint_proxy_core::request::{HttpRequest, HttpResponse};

const CONTENT_TYPE_HEADER: &str = "content-type";

pub fn prepare_grpc_forward_request(request: &HttpRequest) -> FpResult<HttpRequest> {
    if !is_grpc_request_over_http2(request) {
        return Err(FpError::invalid_protocol_data(
            "gRPC transparent forwarding requires HTTP/2 with application/grpc content-type",
        ));
    }

    validate_grpc_payload(&request.body)?;

    let mut forwarded = request.clone();
    forwarded
        .headers
        .extend(preserve_grpc_headers(&request.headers));
    forwarded
        .trailers
        .extend(preserve_grpc_trailers(&request.trailers));
    Ok(forwarded)
}

pub fn finalize_grpc_forward_response(response: &HttpResponse) -> FpResult<HttpResponse> {
    if !response_looks_like_grpc_over_http2(response) {
        return Err(FpError::invalid_protocol_data(
            "gRPC upstream response must preserve application/grpc content-type",
        ));
    }

    validate_grpc_payload(&response.body)?;

    let mut forwarded = response.clone();
    forwarded
        .headers
        .extend(preserve_grpc_headers(&response.headers));
    forwarded
        .trailers
        .extend(preserve_grpc_trailers(&response.trailers));
    Ok(forwarded)
}

pub fn response_looks_like_grpc_over_http2(response: &HttpResponse) -> bool {
    response.version == "HTTP/2"
        && response.headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case(CONTENT_TYPE_HEADER) && grpc_content_type_is_supported(value)
        })
}

fn validate_grpc_payload(payload: &[u8]) -> FpResult<()> {
    if payload.is_empty() {
        return Ok(());
    }

    let _ = parse_grpc_frames(payload)?;
    Ok(())
}
