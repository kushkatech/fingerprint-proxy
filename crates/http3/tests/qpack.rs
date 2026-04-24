use fingerprint_proxy_core::error::ErrorKind;
use fingerprint_proxy_http3::{decode_header_block, encode_header_block, HeaderField};

#[test]
fn qpack_subset_round_trip_is_deterministic() {
    let fields = vec![
        HeaderField {
            name: ":method".to_string(),
            value: "GET".to_string(),
        },
        HeaderField {
            name: ":path".to_string(),
            value: "/".to_string(),
        },
        HeaderField {
            name: "x-test".to_string(),
            value: "v".to_string(),
        },
    ];

    let encoded = encode_header_block(&fields).expect("encode");
    let decoded = decode_header_block(&encoded).expect("decode");
    assert_eq!(decoded, fields);
}

#[test]
fn qpack_subset_decode_rejects_unsupported_representation() {
    let err = decode_header_block(&[0x80]).expect_err("must reject unsupported encoding");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
    assert_eq!(
        err.message,
        "HTTP/3 QPACK decode supports only literal field lines with literal names"
    );
}

#[test]
fn qpack_subset_decode_rejects_truncated_field_bytes() {
    let raw = vec![0x00, 0x03, b'a', b'b'];
    let err = decode_header_block(&raw).expect_err("must reject truncation");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
    assert_eq!(err.message, "HTTP/3 QPACK decode name: truncated bytes");
}
