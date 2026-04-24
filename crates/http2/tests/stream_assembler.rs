use fingerprint_proxy_core::error::ErrorKind;
use fingerprint_proxy_http2::frames::{Frame, FrameHeader, FramePayload, FrameType};
use fingerprint_proxy_http2::{Http2RequestStreamAssembler, StreamEvent, StreamId};

fn hex_bytes(s: &str) -> Vec<u8> {
    let cleaned: String = s.split_whitespace().collect();
    assert!(cleaned.len().is_multiple_of(2));
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    for i in (0..cleaned.len()).step_by(2) {
        out.push(u8::from_str_radix(&cleaned[i..i + 2], 16).unwrap());
    }
    out
}

fn headers_frame(stream_id: StreamId, flags: u8, payload: Vec<u8>) -> Frame {
    Frame {
        header: FrameHeader {
            length: payload.len() as u32,
            frame_type: FrameType::Headers,
            flags,
            stream_id,
        },
        payload: FramePayload::Headers(payload),
    }
}

fn continuation_frame(stream_id: StreamId, flags: u8, payload: Vec<u8>) -> Frame {
    Frame {
        header: FrameHeader {
            length: payload.len() as u32,
            frame_type: FrameType::Continuation,
            flags,
            stream_id,
        },
        payload: FramePayload::Continuation(payload),
    }
}

fn data_frame(stream_id: StreamId, flags: u8, payload: Vec<u8>) -> Frame {
    Frame {
        header: FrameHeader {
            length: payload.len() as u32,
            frame_type: FrameType::Data,
            flags,
            stream_id,
        },
        payload: FramePayload::Data(payload),
    }
}

fn new_decoder() -> fingerprint_proxy_hpack::Decoder {
    fingerprint_proxy_hpack::Decoder::new(fingerprint_proxy_hpack::DecoderConfig {
        max_dynamic_table_size: 4096,
    })
}

fn new_encoder() -> fingerprint_proxy_hpack::Encoder {
    fingerprint_proxy_hpack::Encoder::new(fingerprint_proxy_hpack::EncoderConfig {
        max_dynamic_table_size: 4096,
        use_huffman: false,
    })
}

fn encode_header_block(fields: Vec<(&str, &str)>) -> Vec<u8> {
    let mut encoder = new_encoder();
    let mut out = Vec::new();
    for (n, v) in fields {
        let field = fingerprint_proxy_hpack::HeaderField {
            name: n.as_bytes().to_vec(),
            value: v.as_bytes().to_vec(),
        };
        out.extend_from_slice(&encoder.encode_literal_without_indexing(&field));
    }
    out
}

#[test]
fn headers_only_end_headers_end_stream_yields_complete_request() {
    // RFC 7541 Appendix C.3.1 (no Huffman)
    let block = hex_bytes("82 86 84 41 0f 77 77 77 2e 65 78 61 6d 70 6c 65 2e 63 6f 6d");
    let stream_id = StreamId::new(1).unwrap();
    let mut assembler = Http2RequestStreamAssembler::new(stream_id);
    let mut decoder = new_decoder();

    let ev = assembler
        .push_frame(&mut decoder, headers_frame(stream_id, 0x5, block))
        .expect("push")
        .expect("event");

    match ev {
        StreamEvent::RequestComplete(req) => {
            assert_eq!(req.method, "GET");
            assert_eq!(req.uri, "/");
            assert_eq!(req.version, "HTTP/2");
            assert!(req.body.is_empty());
        }
        _ => panic!("expected complete"),
    }
}

#[test]
fn headers_plus_continuation_yields_complete_request() {
    // RFC 7541 Appendix C.3.1, split across HEADERS + CONTINUATION.
    let block = hex_bytes("82 86 84 41 0f 77 77 77 2e 65 78 61 6d 70 6c 65 2e 63 6f 6d");
    let (first, second) = block.split_at(5);
    let stream_id = StreamId::new(1).unwrap();
    let mut assembler = Http2RequestStreamAssembler::new(stream_id);
    let mut decoder = new_decoder();

    let none = assembler
        .push_frame(&mut decoder, headers_frame(stream_id, 0x1, first.to_vec()))
        .expect("push");
    assert!(none.is_none());

    let ev = assembler
        .push_frame(
            &mut decoder,
            continuation_frame(stream_id, 0x4, second.to_vec()),
        )
        .expect("push")
        .expect("event");

    match ev {
        StreamEvent::RequestComplete(req) => {
            assert_eq!(req.method, "GET");
            assert_eq!(req.uri, "/");
            assert!(req.body.is_empty());
        }
        _ => panic!("expected complete"),
    }
}

#[test]
fn headers_then_data_then_end_stream_collects_body() {
    // RFC 7541 Appendix C.3.1 (no Huffman)
    let block = hex_bytes("82 86 84 41 0f 77 77 77 2e 65 78 61 6d 70 6c 65 2e 63 6f 6d");
    let stream_id = StreamId::new(1).unwrap();
    let mut assembler = Http2RequestStreamAssembler::new(stream_id);
    let mut decoder = new_decoder();

    let ev = assembler
        .push_frame(&mut decoder, headers_frame(stream_id, 0x4, block))
        .expect("push")
        .expect("event");
    match ev {
        StreamEvent::RequestHeadersReady(req) => {
            assert_eq!(req.method, "GET");
        }
        _ => panic!("expected headers ready"),
    }

    let ev = assembler
        .push_frame(&mut decoder, data_frame(stream_id, 0x1, b"abc".to_vec()))
        .expect("push")
        .expect("event");
    match ev {
        StreamEvent::RequestComplete(req) => {
            assert_eq!(req.body, b"abc".to_vec());
        }
        _ => panic!("expected complete"),
    }
}

#[test]
fn data_before_end_headers_is_error() {
    let stream_id = StreamId::new(1).unwrap();
    let mut assembler = Http2RequestStreamAssembler::new(stream_id);
    let mut decoder = new_decoder();

    let none = assembler
        .push_frame(&mut decoder, headers_frame(stream_id, 0x0, vec![0x82]))
        .expect("push");
    assert!(none.is_none());

    let err = assembler
        .push_frame(&mut decoder, data_frame(stream_id, 0x0, b"x".to_vec()))
        .expect_err("must error");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
}

#[test]
fn continuation_after_end_headers_is_error() {
    // RFC 7541 Appendix C.3.1 (no Huffman)
    let block = hex_bytes("82 86 84 41 0f 77 77 77 2e 65 78 61 6d 70 6c 65 2e 63 6f 6d");
    let stream_id = StreamId::new(1).unwrap();
    let mut assembler = Http2RequestStreamAssembler::new(stream_id);
    let mut decoder = new_decoder();

    let _ = assembler
        .push_frame(&mut decoder, headers_frame(stream_id, 0x4, block))
        .expect("push");

    let err = assembler
        .push_frame(&mut decoder, continuation_frame(stream_id, 0x4, vec![0x00]))
        .expect_err("must error");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
}

#[test]
fn headers_data_then_trailers_headers_end_stream_captures_trailers() {
    // Initial request headers (RFC 7541 Appendix C.3.1 no Huffman)
    let block = hex_bytes("82 86 84 41 0f 77 77 77 2e 65 78 61 6d 70 6c 65 2e 63 6f 6d");
    let stream_id = StreamId::new(1).unwrap();
    let mut assembler = Http2RequestStreamAssembler::new(stream_id);
    let mut decoder = new_decoder();

    let ev = assembler
        .push_frame(&mut decoder, headers_frame(stream_id, 0x4, block))
        .expect("push")
        .expect("event");
    assert!(matches!(ev, StreamEvent::RequestHeadersReady(_)));

    let none = assembler
        .push_frame(&mut decoder, data_frame(stream_id, 0x0, b"abc".to_vec()))
        .expect("push");
    assert!(none.is_none());

    let trailer_block = encode_header_block(vec![("x-trailer", "v")]);
    let ev = assembler
        .push_frame(
            &mut decoder,
            headers_frame(stream_id, 0x5, trailer_block), // END_HEADERS|END_STREAM
        )
        .expect("push")
        .expect("event");

    match ev {
        StreamEvent::RequestComplete(req) => {
            assert_eq!(req.body, b"abc".to_vec());
            assert_eq!(req.trailers.get("x-trailer").map(String::as_str), Some("v"));
        }
        _ => panic!("expected complete"),
    }
}

#[test]
fn headers_then_data_end_stream_has_empty_trailers() {
    // RFC 7541 Appendix C.3.1 (no Huffman)
    let block = hex_bytes("82 86 84 41 0f 77 77 77 2e 65 78 61 6d 70 6c 65 2e 63 6f 6d");
    let stream_id = StreamId::new(1).unwrap();
    let mut assembler = Http2RequestStreamAssembler::new(stream_id);
    let mut decoder = new_decoder();

    let _ = assembler
        .push_frame(&mut decoder, headers_frame(stream_id, 0x4, block))
        .expect("push");

    let ev = assembler
        .push_frame(&mut decoder, data_frame(stream_id, 0x1, b"abc".to_vec()))
        .expect("push")
        .expect("event");

    match ev {
        StreamEvent::RequestComplete(req) => {
            assert_eq!(req.body, b"abc".to_vec());
            assert!(req.trailers.is_empty());
        }
        _ => panic!("expected complete"),
    }
}

#[test]
fn trailers_with_pseudo_header_is_error() {
    // Initial request headers (RFC 7541 Appendix C.3.1 no Huffman)
    let block = hex_bytes("82 86 84 41 0f 77 77 77 2e 65 78 61 6d 70 6c 65 2e 63 6f 6d");
    let stream_id = StreamId::new(1).unwrap();
    let mut assembler = Http2RequestStreamAssembler::new(stream_id);
    let mut decoder = new_decoder();

    let _ = assembler
        .push_frame(&mut decoder, headers_frame(stream_id, 0x4, block))
        .expect("push");

    let none = assembler
        .push_frame(&mut decoder, data_frame(stream_id, 0x0, b"abc".to_vec()))
        .expect("push");
    assert!(none.is_none());

    let trailer_block = encode_header_block(vec![(":path", "/")]);
    let err = assembler
        .push_frame(&mut decoder, headers_frame(stream_id, 0x5, trailer_block))
        .expect_err("must error");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
}
