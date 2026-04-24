use fingerprint_proxy_core::error::ErrorKind;
use fingerprint_proxy_core::request::HttpResponse;
use fingerprint_proxy_hpack::{Decoder, DecoderConfig, Encoder, EncoderConfig};
use fingerprint_proxy_http2::{
    decode_header_block, encode_http2_response_headers, map_headers_to_response, HeaderBlockInput,
};

fn new_encoder() -> Encoder {
    Encoder::new(EncoderConfig {
        max_dynamic_table_size: 4096,
        use_huffman: false,
    })
}

fn new_decoder() -> Decoder {
    Decoder::new(DecoderConfig {
        max_dynamic_table_size: 4096,
    })
}

#[test]
fn encodes_then_decodes_then_maps_response_headers() {
    let mut encoder = new_encoder();
    let mut decoder = new_decoder();

    let mut resp = HttpResponse {
        status: Some(200),
        ..Default::default()
    };
    resp.headers
        .insert("content-type".to_string(), "text/plain".to_string());

    let block = encode_http2_response_headers(&mut encoder, &resp).expect("encode");
    let fields = decode_header_block(
        &mut decoder,
        HeaderBlockInput {
            first_fragment: &block,
            continuation_fragments: &[],
        },
    )
    .expect("decode");
    let mapped = map_headers_to_response(&fields).expect("map");

    assert_eq!(mapped.version, "HTTP/2");
    assert_eq!(mapped.status, Some(200));
    assert_eq!(
        mapped.headers.get("content-type").map(String::as_str),
        Some("text/plain")
    );
}

#[test]
fn rejects_uppercase_header_name() {
    let mut encoder = new_encoder();

    let mut resp = HttpResponse {
        status: Some(200),
        ..Default::default()
    };
    resp.headers
        .insert("Content-Type".to_string(), "text/plain".to_string());

    let err = encode_http2_response_headers(&mut encoder, &resp).expect_err("must reject");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
}

#[test]
fn rejects_connection_specific_header() {
    let mut encoder = new_encoder();

    let mut resp = HttpResponse {
        status: Some(200),
        ..Default::default()
    };
    resp.headers
        .insert("connection".to_string(), "keep-alive".to_string());

    let err = encode_http2_response_headers(&mut encoder, &resp).expect_err("must reject");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
}

#[test]
fn missing_status_is_error() {
    let mut encoder = new_encoder();

    let resp = HttpResponse::default();
    let err = encode_http2_response_headers(&mut encoder, &resp).expect_err("must reject");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
    assert_eq!(
        err.message,
        "missing required HTTP/2 pseudo-header: :status"
    );
}
