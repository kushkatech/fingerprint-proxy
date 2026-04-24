use fingerprint_proxy_core::error::FpResult;
use fingerprint_proxy_core::request::{HttpRequest, HttpResponse};
use fingerprint_proxy_grpc::{
    finalize_grpc_forward_response, is_grpc_request_over_http2, prepare_grpc_forward_request,
};

pub fn grpc_http2_request_requires_transparent_forwarding(request: &HttpRequest) -> bool {
    is_grpc_request_over_http2(request)
}

pub fn prepare_grpc_http2_request(request: &HttpRequest) -> FpResult<HttpRequest> {
    if !grpc_http2_request_requires_transparent_forwarding(request) {
        return Ok(request.clone());
    }

    prepare_grpc_forward_request(request)
}

pub fn finalize_grpc_http2_response(
    request: &HttpRequest,
    response: &HttpResponse,
) -> FpResult<HttpResponse> {
    if !grpc_http2_request_requires_transparent_forwarding(request) {
        return Ok(response.clone());
    }

    finalize_grpc_forward_response(response)
}
