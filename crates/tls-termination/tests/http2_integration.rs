use fingerprint_proxy_core::error::ErrorKind;
use fingerprint_proxy_http2::frames::{
    serialize_frame, Frame, FrameHeader, FramePayload, FrameType,
};
use fingerprint_proxy_http2::{ConnectionPreface, Settings, StreamId};
use fingerprint_proxy_tls_termination::Http2ProtocolParser;

fn settings_frame_bytes() -> Vec<u8> {
    let frame = Frame {
        header: FrameHeader {
            length: 0,
            frame_type: FrameType::Settings,
            flags: 0,
            stream_id: StreamId::connection(),
        },
        payload: FramePayload::Settings {
            ack: false,
            settings: Settings::new(Vec::new()),
        },
    };
    serialize_frame(&frame).expect("serialize settings frame")
}

#[test]
fn parses_preface_and_complete_frame() {
    let mut parser = Http2ProtocolParser::new();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(ConnectionPreface::CLIENT_BYTES);
    bytes.extend_from_slice(&settings_frame_bytes());

    let frames = parser.push_bytes(&bytes).expect("parse");
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].header.frame_type, FrameType::Settings);
    assert!(parser.preface_consumed());
    assert_eq!(parser.pending_bytes(), 0);
}

#[test]
fn partial_preface_is_buffered_until_complete() {
    let mut parser = Http2ProtocolParser::new();
    let preface = ConnectionPreface::CLIENT_BYTES.as_slice();

    let first = &preface[..10];
    let second = &preface[10..];

    let out1 = parser.push_bytes(first).expect("first preface chunk");
    assert!(out1.is_empty());
    assert!(!parser.preface_consumed());
    assert_eq!(parser.pending_bytes(), first.len());

    let out2 = parser.push_bytes(second).expect("second preface chunk");
    assert!(out2.is_empty());
    assert!(parser.preface_consumed());
    assert_eq!(parser.pending_bytes(), 0);
}

#[test]
fn partial_frame_is_buffered_until_complete() {
    let mut parser = Http2ProtocolParser::new();
    let frame = settings_frame_bytes();

    let mut first = Vec::new();
    first.extend_from_slice(ConnectionPreface::CLIENT_BYTES);
    first.extend_from_slice(&frame[..5]);
    let out1 = parser.push_bytes(&first).expect("first chunk");
    assert!(out1.is_empty());
    assert!(parser.preface_consumed());
    assert_eq!(parser.pending_bytes(), 5);

    let out2 = parser.push_bytes(&frame[5..]).expect("second chunk");
    assert_eq!(out2.len(), 1);
    assert_eq!(out2[0].header.frame_type, FrameType::Settings);
    assert_eq!(parser.pending_bytes(), 0);
}

#[test]
fn invalid_preface_is_rejected() {
    let mut parser = Http2ProtocolParser::new();
    let err = parser
        .push_bytes(b"NOT-HTTP2-PREFACE")
        .expect_err("must reject invalid preface");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
    assert_eq!(err.message, "HTTP/2 connection preface mismatch");
}

#[test]
fn invalid_frame_after_preface_is_rejected() {
    let mut parser = Http2ProtocolParser::new();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(ConnectionPreface::CLIENT_BYTES);
    bytes.extend_from_slice(&[0u8, 0u8, 0u8, 0x0, 0x0, 0, 0, 0, 0]);

    let err = parser.push_bytes(&bytes).expect_err("must reject frame");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
    assert!(err.message.starts_with("HTTP/2 frame decode error: "));
}
