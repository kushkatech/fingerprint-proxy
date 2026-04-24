use fingerprint_proxy_core::error::ErrorKind;
use fingerprint_proxy_websocket::{parse_websocket_frames, WebSocketOpcode};

#[test]
fn parses_masked_text_frame() {
    let bytes = [
        0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58,
    ];
    let frames = parse_websocket_frames(&bytes).expect("frame parses");
    assert_eq!(frames.len(), 1);
    assert!(frames[0].fin);
    assert!(frames[0].masked);
    assert_eq!(frames[0].opcode, WebSocketOpcode::Text);
    assert_eq!(frames[0].payload, b"Hello");
}

#[test]
fn parses_unmasked_binary_frame_with_extended_length() {
    let mut bytes = vec![0x82, 126, 0x00, 0x7e];
    bytes.extend(std::iter::repeat_n(0xAB, 126));

    let frames = parse_websocket_frames(&bytes).expect("frame parses");
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].opcode, WebSocketOpcode::Binary);
    assert_eq!(frames[0].payload.len(), 126);
    assert!(frames[0].payload.iter().all(|byte| *byte == 0xAB));
}

#[test]
fn rejects_reserved_bits() {
    let bytes = [0xC1, 0x00];
    let error = parse_websocket_frames(&bytes).expect_err("frame is rejected");
    assert_eq!(error.kind, ErrorKind::InvalidProtocolData);
    assert!(error.message.contains("reserved bits"));
}

#[test]
fn rejects_fragmented_control_frame() {
    let bytes = [0x09, 0x00];
    let error = parse_websocket_frames(&bytes).expect_err("frame is rejected");
    assert_eq!(error.kind, ErrorKind::InvalidProtocolData);
    assert!(error.message.contains("fragmented control frames"));
}

#[test]
fn rejects_truncated_masking_key() {
    let bytes = [0x81, 0x85, 0x37, 0xfa];
    let error = parse_websocket_frames(&bytes).expect_err("frame is rejected");
    assert_eq!(error.kind, ErrorKind::InvalidProtocolData);
    assert!(error.message.contains("truncated masking key"));
}

#[test]
fn rejects_truncated_payload() {
    let bytes = [0x82, 0x02, 0xAA];
    let error = parse_websocket_frames(&bytes).expect_err("frame is rejected");
    assert_eq!(error.kind, ErrorKind::InvalidProtocolData);
    assert!(error.message.contains("truncated payload"));
}
