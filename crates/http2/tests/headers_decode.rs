use fingerprint_proxy_hpack::{
    Decoder, DecoderConfig, Encoder, EncoderConfig, HeaderField as HpackField,
};
use fingerprint_proxy_http2::{decode_header_block, HeaderBlockInput, HeaderField};

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
fn decodes_rfc7541_appendix_c_example() {
    // RFC 7541 Appendix C.3.1 (no Huffman)
    let block = hex_bytes("82 86 84 41 0f 77 77 77 2e 65 78 61 6d 70 6c 65 2e 63 6f 6d");

    let mut decoder = new_decoder();
    let fields = decode_header_block(
        &mut decoder,
        HeaderBlockInput {
            first_fragment: &block,
            continuation_fragments: &[],
        },
    )
    .expect("decode");

    assert_eq!(
        fields,
        vec![
            HeaderField {
                name: ":method".to_string(),
                value: "GET".to_string(),
            },
            HeaderField {
                name: ":scheme".to_string(),
                value: "http".to_string(),
            },
            HeaderField {
                name: ":path".to_string(),
                value: "/".to_string(),
            },
            HeaderField {
                name: ":authority".to_string(),
                value: "www.example.com".to_string(),
            },
        ]
    );
}

#[test]
fn rejects_uppercase_header_name() {
    let mut encoder = Encoder::new(EncoderConfig {
        max_dynamic_table_size: 4096,
        use_huffman: false,
    });
    let mut decoder = new_decoder();

    let block = encoder.encode_literal_without_indexing(&HpackField {
        name: b"Host".to_vec(),
        value: b"example.com".to_vec(),
    });

    let err = decode_header_block(
        &mut decoder,
        HeaderBlockInput {
            first_fragment: &block,
            continuation_fragments: &[],
        },
    )
    .expect_err("must reject");

    assert_eq!(
        err.kind,
        fingerprint_proxy_core::error::ErrorKind::InvalidProtocolData
    );
}

#[test]
fn concatenates_fragments_in_order() {
    // RFC 7541 Appendix C.3.1 (no Huffman), split into two fragments
    let block = hex_bytes("82 86 84 41 0f 77 77 77 2e 65 78 61 6d 70 6c 65 2e 63 6f 6d");
    let (first, second) = block.split_at(5);

    let mut decoder = new_decoder();
    let fields = decode_header_block(
        &mut decoder,
        HeaderBlockInput {
            first_fragment: first,
            continuation_fragments: &[second],
        },
    )
    .expect("decode");

    assert_eq!(fields.len(), 4);
    assert_eq!(fields[3].name, ":authority");
    assert_eq!(fields[3].value, "www.example.com");
}
