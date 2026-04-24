use crate::headers::{decode_header_block, HeaderBlockInput};
use crate::request_map::map_headers_to_request;
use fingerprint_proxy_core::error::FpResult;
use fingerprint_proxy_core::request::HttpRequest;

pub fn decode_http2_request_headers(
    decoder: &mut fingerprint_proxy_hpack::Decoder,
    first_fragment: &[u8],
    continuation_fragments: &[&[u8]],
) -> FpResult<HttpRequest> {
    let fields = decode_header_block(
        decoder,
        HeaderBlockInput {
            first_fragment,
            continuation_fragments,
        },
    )?;
    map_headers_to_request(&fields)
}
