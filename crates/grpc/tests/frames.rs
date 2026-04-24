use fingerprint_proxy_core::error::ErrorKind;
use fingerprint_proxy_grpc::{parse_grpc_frames, GrpcFrame};

#[test]
fn parses_multiple_valid_length_prefixed_frames() {
    let payload = vec![
        0x00, 0x00, 0x00, 0x00, 0x02, b'o', b'k', // uncompressed "ok"
        0x01, 0x00, 0x00, 0x00, 0x03, b'f', b'o', b'o', // compressed "foo"
    ];

    let frames = parse_grpc_frames(&payload).expect("parse frames");
    assert_eq!(
        frames,
        vec![
            GrpcFrame {
                compressed: false,
                message: b"ok".to_vec(),
            },
            GrpcFrame {
                compressed: true,
                message: b"foo".to_vec(),
            },
        ]
    );
}

#[test]
fn empty_payload_has_no_frames() {
    let frames = parse_grpc_frames(&[]).expect("empty payload parses");
    assert!(frames.is_empty());
}

#[test]
fn rejects_invalid_compressed_flag() {
    let payload = vec![0x02, 0x00, 0x00, 0x00, 0x00];
    let err = parse_grpc_frames(&payload).expect_err("invalid flag must fail");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
    assert_eq!(
        err.message,
        "gRPC frame parse failed: invalid compressed flag"
    );
}

#[test]
fn rejects_truncated_header_and_payload() {
    let header_err =
        parse_grpc_frames(&[0x00, 0x00, 0x00, 0x00]).expect_err("truncated header must fail");
    assert_eq!(header_err.kind, ErrorKind::InvalidProtocolData);
    assert_eq!(
        header_err.message,
        "gRPC frame parse failed: truncated frame header"
    );

    let payload_err = parse_grpc_frames(&[0x00, 0x00, 0x00, 0x00, 0x02, b'o'])
        .expect_err("truncated payload must fail");
    assert_eq!(payload_err.kind, ErrorKind::InvalidProtocolData);
    assert_eq!(
        payload_err.message,
        "gRPC frame parse failed: truncated message payload"
    );
}
