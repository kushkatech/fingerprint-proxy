use fingerprint_proxy_core::error::ErrorKind;
use fingerprint_proxy_http3::frames::{parse_frame, serialize_frame, Frame, FrameType};
use fingerprint_proxy_http3::{Http3RequestStreamAssembler, StreamEvent};

#[test]
fn frame_round_trip_headers_and_data() {
    let h = Frame::new(FrameType::Headers, b"hdr".to_vec());
    let hb = serialize_frame(&h).expect("serialize");
    let (h2, used) = parse_frame(&hb).expect("parse");
    assert_eq!(used, hb.len());
    assert_eq!(h2, h);

    let d = Frame::new(FrameType::Data, b"body".to_vec());
    let db = serialize_frame(&d).expect("serialize");
    let (d2, used) = parse_frame(&db).expect("parse");
    assert_eq!(used, db.len());
    assert_eq!(d2, d);
}

#[test]
fn invalid_varint_is_invalid_protocol_data() {
    let err = parse_frame(&[0x40]).expect_err("must fail");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
}

#[test]
fn truncated_payload_is_invalid_protocol_data() {
    let err = parse_frame(&[0x00, 0x03, 0x41]).expect_err("must fail");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
}

#[test]
fn headers_only_request_completes_on_finish() {
    let mut asm = Http3RequestStreamAssembler::new();
    let ev = asm
        .push_frame(Frame::new(FrameType::Headers, b"h".to_vec()))
        .expect("push");
    assert_eq!(ev, vec![StreamEvent::RequestHeadersReady(b"h".to_vec())]);

    let done = asm.finish_stream().expect("finish");
    assert_eq!(
        done,
        vec![StreamEvent::RequestComplete {
            headers: b"h".to_vec(),
            trailers: None,
            body: Vec::new()
        }]
    );
}

#[test]
fn headers_then_data_collects_body() {
    let mut asm = Http3RequestStreamAssembler::new();
    let _ = asm
        .push_frame(Frame::new(FrameType::Headers, b"h".to_vec()))
        .expect("push headers");
    let _ = asm
        .push_frame(Frame::new(FrameType::Data, b"abc".to_vec()))
        .expect("push data");
    let done = asm.finish_stream().expect("finish");
    assert_eq!(
        done,
        vec![StreamEvent::RequestComplete {
            headers: b"h".to_vec(),
            trailers: None,
            body: b"abc".to_vec()
        }]
    );
}

#[test]
fn data_before_headers_is_error() {
    let mut asm = Http3RequestStreamAssembler::new();
    let err = asm
        .push_frame(Frame::new(FrameType::Data, b"x".to_vec()))
        .expect_err("must error");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
}

#[test]
fn second_headers_is_error() {
    let mut asm = Http3RequestStreamAssembler::new();
    let _ = asm
        .push_frame(Frame::new(FrameType::Headers, b"h1".to_vec()))
        .expect("push headers");
    let _ = asm
        .push_frame(Frame::new(FrameType::Data, b"abc".to_vec()))
        .expect("push data");
    let _ = asm
        .push_frame(Frame::new(FrameType::Headers, b"t".to_vec()))
        .expect("push trailers");
    let err = asm
        .push_frame(Frame::new(FrameType::Headers, b"h2".to_vec()))
        .expect_err("must error");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
}

#[test]
fn trailers_headers_after_data_are_captured() {
    let mut asm = Http3RequestStreamAssembler::new();
    let _ = asm
        .push_frame(Frame::new(FrameType::Headers, b"h".to_vec()))
        .expect("push headers");
    let _ = asm
        .push_frame(Frame::new(FrameType::Data, b"abc".to_vec()))
        .expect("push data");
    let _ = asm
        .push_frame(Frame::new(FrameType::Headers, b"tr".to_vec()))
        .expect("push trailers");
    let done = asm.finish_stream().expect("finish");
    assert_eq!(
        done,
        vec![StreamEvent::RequestComplete {
            headers: b"h".to_vec(),
            trailers: Some(b"tr".to_vec()),
            body: b"abc".to_vec()
        }]
    );
}

#[test]
fn trailers_before_data_is_error() {
    let mut asm = Http3RequestStreamAssembler::new();
    let _ = asm
        .push_frame(Frame::new(FrameType::Headers, b"h".to_vec()))
        .expect("push headers");
    let err = asm
        .push_frame(Frame::new(FrameType::Headers, b"tr".to_vec()))
        .expect_err("must error");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
}
