use fingerprint_proxy_hpack::huffman;
use fingerprint_proxy_hpack::{
    Decoder, DecoderConfig, Encoder, EncoderConfig, HeaderField, HpackError,
};

fn hex_bytes(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let cleaned: String = s.split_whitespace().collect();
    assert!(cleaned.len().is_multiple_of(2));
    for i in (0..cleaned.len()).step_by(2) {
        out.push(u8::from_str_radix(&cleaned[i..i + 2], 16).unwrap());
    }
    out
}

#[test]
fn integer_encoding_examples() {
    let mut out = Vec::new();
    fingerprint_proxy_hpack::integer::encode_integer(10, 5, 0x00, &mut out);
    assert_eq!(out, vec![0x0a]);

    out.clear();
    fingerprint_proxy_hpack::integer::encode_integer(1337, 5, 0x00, &mut out);
    assert_eq!(out, vec![0x1f, 0x9a, 0x0a]);

    let mut cursor = 1usize;
    let decoded = fingerprint_proxy_hpack::integer::decode_integer(out[0], 5, &out, &mut cursor)
        .expect("decode");
    assert_eq!(decoded, 1337);
    assert_eq!(cursor, out.len());
}

#[test]
fn huffman_round_trip() {
    let input = b"www.example.com";
    let encoded = huffman::encode(input);
    let decoded = huffman::decode(&encoded).expect("decode");
    assert_eq!(decoded, input);
}

#[test]
fn huffman_rejects_bad_padding() {
    let input = b"www.example.com";
    let mut encoded = huffman::encode(input);
    assert!(!encoded.is_empty());
    *encoded.last_mut().unwrap() &= 0xfe;
    assert_eq!(
        huffman::decode(&encoded),
        Err(HpackError::InvalidHuffmanEncoding)
    );
}

#[test]
fn request_examples_without_huffman() {
    // RFC 7541 Appendix C.3.1 / C.3.2
    let first = hex_bytes("82 86 84 41 0f 77 77 77 2e 65 78 61 6d 70 6c 65 2e 63 6f 6d");
    let second = hex_bytes("82 86 84 be 58 08 6e 6f 2d 63 61 63 68 65");

    let mut dec = Decoder::new(DecoderConfig {
        max_dynamic_table_size: 4096,
    });

    let first_headers = dec.decode(&first).expect("decode first");
    assert_eq!(
        first_headers,
        vec![
            HeaderField {
                name: b":method".to_vec(),
                value: b"GET".to_vec(),
            },
            HeaderField {
                name: b":scheme".to_vec(),
                value: b"http".to_vec(),
            },
            HeaderField {
                name: b":path".to_vec(),
                value: b"/".to_vec(),
            },
            HeaderField {
                name: b":authority".to_vec(),
                value: b"www.example.com".to_vec(),
            },
        ]
    );

    let second_headers = dec.decode(&second).expect("decode second");
    assert_eq!(
        second_headers,
        vec![
            HeaderField {
                name: b":method".to_vec(),
                value: b"GET".to_vec(),
            },
            HeaderField {
                name: b":scheme".to_vec(),
                value: b"http".to_vec(),
            },
            HeaderField {
                name: b":path".to_vec(),
                value: b"/".to_vec(),
            },
            HeaderField {
                name: b":authority".to_vec(),
                value: b"www.example.com".to_vec(),
            },
            HeaderField {
                name: b"cache-control".to_vec(),
                value: b"no-cache".to_vec(),
            },
        ]
    );
}

#[test]
fn request_examples_with_huffman() {
    // RFC 7541 Appendix C.4.1 / C.4.2
    let first = hex_bytes("82 86 84 41 8c f1 e3 c2 e5 f2 3a 6b a0 ab 90 f4 ff");
    let second = hex_bytes("82 86 84 be 58 86 a8 eb 10 64 9c bf");

    let mut dec = Decoder::new(DecoderConfig {
        max_dynamic_table_size: 4096,
    });

    let _ = dec.decode(&first).expect("decode first");
    let second_headers = dec.decode(&second).expect("decode second");

    assert_eq!(
        second_headers,
        vec![
            HeaderField {
                name: b":method".to_vec(),
                value: b"GET".to_vec(),
            },
            HeaderField {
                name: b":scheme".to_vec(),
                value: b"http".to_vec(),
            },
            HeaderField {
                name: b":path".to_vec(),
                value: b"/".to_vec(),
            },
            HeaderField {
                name: b":authority".to_vec(),
                value: b"www.example.com".to_vec(),
            },
            HeaderField {
                name: b"cache-control".to_vec(),
                value: b"no-cache".to_vec(),
            },
        ]
    );
}

#[test]
fn dynamic_table_size_update_must_be_first() {
    let mut dec = Decoder::new(DecoderConfig {
        max_dynamic_table_size: 4096,
    });
    let block = vec![0x82, 0x20]; // Indexed header, then table-size update => invalid
    assert_eq!(dec.decode(&block), Err(HpackError::InvalidHeaderBlock));
}

#[test]
fn encoder_decoder_smoke_round_trip() {
    let mut enc = Encoder::new(EncoderConfig {
        max_dynamic_table_size: 4096,
        use_huffman: false,
    });
    let mut dec = Decoder::new(DecoderConfig {
        max_dynamic_table_size: 4096,
    });

    let headers = vec![
        HeaderField {
            name: b"custom-key".to_vec(),
            value: b"custom-value".to_vec(),
        },
        HeaderField {
            name: b"cache-control".to_vec(),
            value: b"no-cache".to_vec(),
        },
    ];

    let mut block = Vec::new();
    for h in &headers {
        block.extend_from_slice(&enc.encode_literal_with_incremental_indexing(h));
    }

    let decoded = dec.decode(&block).expect("decode");
    assert_eq!(decoded, headers);
}
