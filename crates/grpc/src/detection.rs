use fingerprint_proxy_core::request::HttpRequest;

const HTTP2_VERSION: &str = "HTTP/2";
const CONTENT_TYPE_HEADER: &str = "content-type";
const GRPC_CONTENT_TYPE: &str = "application/grpc";

pub fn is_grpc_request_over_http2(request: &HttpRequest) -> bool {
    if request.version != HTTP2_VERSION {
        return false;
    }

    request.headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case(CONTENT_TYPE_HEADER) && grpc_content_type_is_supported(value)
    })
}

pub fn grpc_content_type_is_supported(value: &str) -> bool {
    let media_type = value.split(';').next().unwrap_or("").trim();
    media_type.eq_ignore_ascii_case(GRPC_CONTENT_TYPE)
}
