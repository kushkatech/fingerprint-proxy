use fingerprint_proxy_core::error::ErrorKind;
use fingerprint_proxy_hpack::{
    Decoder, DecoderConfig, Encoder, EncoderConfig, HeaderField as HpackField,
};
use fingerprint_proxy_http2::decode_http2_request_headers;

fn hex_bytes(s: &str) -> Vec<u8> {
    let cleaned: String = s.split_whitespace().collect();
    assert!(cleaned.len().is_multiple_of(2));
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    for i in (0..cleaned.len()).step_by(2) {
        out.push(u8::from_str_radix(&cleaned[i..i + 2], 16).unwrap());
    }
    out
}

fn new_decoder() -> Decoder {
    Decoder::new(DecoderConfig {
        max_dynamic_table_size: 4096,
    })
}

#[test]
fn decodes_rfc7541_appendix_c_request_headers_to_http_request() {
    // RFC 7541 Appendix C.3.1 (no Huffman)
    let block = hex_bytes("82 86 84 41 0f 77 77 77 2e 65 78 61 6d 70 6c 65 2e 63 6f 6d");

    let mut decoder = new_decoder();
    let req = decode_http2_request_headers(&mut decoder, &block, &[]).expect("decode+map");

    assert_eq!(req.version, "HTTP/2");
    assert_eq!(req.method, "GET");
    assert_eq!(req.uri, "/");
    assert!(req.headers.is_empty());
}

#[test]
fn concatenates_fragments_before_mapping() {
    // RFC 7541 Appendix C.3.1 (no Huffman), split into two fragments
    let block = hex_bytes("82 86 84 41 0f 77 77 77 2e 65 78 61 6d 70 6c 65 2e 63 6f 6d");
    let (first, second) = block.split_at(5);

    let mut decoder = new_decoder();
    let req = decode_http2_request_headers(&mut decoder, first, &[second]).expect("decode+map");

    assert_eq!(req.method, "GET");
    assert_eq!(req.uri, "/");
}

#[test]
fn rejects_uppercase_header_name_via_composed_helper() {
    let mut encoder = Encoder::new(EncoderConfig {
        max_dynamic_table_size: 4096,
        use_huffman: false,
    });
    let mut decoder = new_decoder();

    let block = encoder.encode_literal_without_indexing(&HpackField {
        name: b"Host".to_vec(),
        value: b"example.com".to_vec(),
    });

    let err = decode_http2_request_headers(&mut decoder, &block, &[]).expect_err("must reject");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
}

#[test]
fn missing_method_is_invalid_protocol_data() {
    let mut encoder = Encoder::new(EncoderConfig {
        max_dynamic_table_size: 4096,
        use_huffman: false,
    });
    let mut decoder = new_decoder();

    let block = encoder.encode_literal_without_indexing(&HpackField {
        name: b":path".to_vec(),
        value: b"/".to_vec(),
    });

    let err = decode_http2_request_headers(&mut decoder, &block, &[]).expect_err("must reject");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
    assert_eq!(
        err.message,
        "missing required HTTP/2 pseudo-header: :method"
    );
}
