use fingerprint_proxy_core::error::ErrorKind;
use fingerprint_proxy_http3::{parse_frames, serialize_frame, Frame, FrameType};

#[test]
fn parse_frames_decodes_multiple_frames_in_order() {
    let f1 = Frame::new(FrameType::Headers, b"h".to_vec());
    let f2 = Frame::new(FrameType::Data, b"abc".to_vec());
    let f3 = Frame::new(FrameType::Unknown(0x21), b"x".to_vec());

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&serialize_frame(&f1).expect("serialize f1"));
    bytes.extend_from_slice(&serialize_frame(&f2).expect("serialize f2"));
    bytes.extend_from_slice(&serialize_frame(&f3).expect("serialize f3"));

    let parsed = parse_frames(&bytes).expect("parse frames");
    assert_eq!(parsed, vec![f1, f2, f3]);
}

#[test]
fn parse_frames_returns_invalid_protocol_data_on_truncated_payload() {
    let err = parse_frames(&[0x00, 0x03, 0x61]).expect_err("must fail");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
    assert_eq!(err.message, "HTTP/3 truncated frame payload");
}
