use fingerprint_proxy_core::error::ErrorKind;
use fingerprint_proxy_core::request::HttpResponse;
use fingerprint_proxy_hpack::{Decoder, DecoderConfig, Encoder, EncoderConfig};
use fingerprint_proxy_http2::frames::{FramePayload, FrameType};
use fingerprint_proxy_http2::{
    decode_header_block, encode_http2_response_frames, map_headers_to_response, HeaderBlockInput,
    StreamId,
};

fn new_encoder() -> Encoder {
    Encoder::new(EncoderConfig {
        max_dynamic_table_size: 4096,
        use_huffman: false,
    })
}

fn new_decoder() -> Decoder {
    Decoder::new(DecoderConfig {
        max_dynamic_table_size: 4096,
    })
}

#[test]
fn empty_body_emits_headers_only_with_end_stream() {
    let mut encoder = new_encoder();
    let mut decoder = new_decoder();

    let mut resp = HttpResponse {
        status: Some(200),
        ..Default::default()
    };
    resp.headers
        .insert("content-type".to_string(), "text/plain".to_string());

    let stream_id = StreamId::new(1).unwrap();
    let frames = encode_http2_response_frames(&mut encoder, stream_id, &resp).expect("encode");
    assert_eq!(frames.len(), 1);

    let f = &frames[0];
    assert_eq!(f.header.stream_id, stream_id);
    assert_eq!(f.header.frame_type, FrameType::Headers);
    assert_eq!(f.header.flags & 0x4, 0x4); // END_HEADERS
    assert_eq!(f.header.flags & 0x1, 0x1); // END_STREAM

    let FramePayload::Headers(block) = &f.payload else {
        panic!("expected HEADERS payload");
    };

    let fields = decode_header_block(
        &mut decoder,
        HeaderBlockInput {
            first_fragment: block,
            continuation_fragments: &[],
        },
    )
    .expect("decode");
    let mapped = map_headers_to_response(&fields).expect("map");

    assert_eq!(mapped.version, "HTTP/2");
    assert_eq!(mapped.status, Some(200));
    assert_eq!(
        mapped.headers.get("content-type").map(String::as_str),
        Some("text/plain")
    );
}

#[test]
fn non_empty_body_emits_headers_then_data_with_end_stream_on_data() {
    let mut encoder = new_encoder();

    let resp = HttpResponse {
        status: Some(200),
        body: b"abc".to_vec(),
        ..Default::default()
    };

    let stream_id = StreamId::new(1).unwrap();
    let frames = encode_http2_response_frames(&mut encoder, stream_id, &resp).expect("encode");
    assert_eq!(frames.len(), 2);

    let headers = &frames[0];
    assert_eq!(headers.header.stream_id, stream_id);
    assert_eq!(headers.header.frame_type, FrameType::Headers);
    assert_eq!(headers.header.flags & 0x4, 0x4); // END_HEADERS
    assert_eq!(headers.header.flags & 0x1, 0x0); // no END_STREAM

    let data = &frames[1];
    assert_eq!(data.header.stream_id, stream_id);
    assert_eq!(data.header.frame_type, FrameType::Data);
    assert_eq!(data.header.flags & 0x1, 0x1); // END_STREAM
    let FramePayload::Data(bytes) = &data.payload else {
        panic!("expected DATA payload");
    };
    assert_eq!(bytes, b"abc");
}

#[test]
fn large_body_is_split_into_default_sized_data_frames_with_end_stream_on_final_data() {
    let mut encoder = new_encoder();
    let body: Vec<u8> = (0..40_000).map(|i| (i % 251) as u8).collect();

    let resp = HttpResponse {
        status: Some(200),
        body: body.clone(),
        ..Default::default()
    };

    let stream_id = StreamId::new(1).unwrap();
    let frames = encode_http2_response_frames(&mut encoder, stream_id, &resp).expect("encode");
    assert_eq!(frames.len(), 4);
    assert_eq!(frames[0].header.frame_type, FrameType::Headers);

    let mut reassembled = Vec::new();
    for (index, frame) in frames[1..].iter().enumerate() {
        assert_eq!(frame.header.stream_id, stream_id);
        assert_eq!(frame.header.frame_type, FrameType::Data);
        assert!(frame.header.length <= 16_384);
        assert_eq!(
            frame.header.flags & 0x1,
            if index == 2 { 0x1 } else { 0x0 },
            "only the final DATA frame may end the stream"
        );

        let FramePayload::Data(bytes) = &frame.payload else {
            panic!("expected DATA payload");
        };
        assert_eq!(frame.header.length as usize, bytes.len());
        reassembled.extend_from_slice(bytes);
    }
    assert_eq!(reassembled, body);
}

#[test]
fn stream_id_zero_is_invalid() {
    let mut encoder = new_encoder();
    let resp = HttpResponse {
        status: Some(200),
        ..Default::default()
    };

    let err =
        encode_http2_response_frames(&mut encoder, StreamId::connection(), &resp).expect_err("err");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
}

#[test]
fn headers_body_and_trailers_emit_headers_data_and_trailing_headers_with_end_stream_on_trailers() {
    let mut encoder = new_encoder();
    let stream_id = StreamId::new(1).unwrap();

    let mut resp = HttpResponse {
        status: Some(200),
        body: b"abc".to_vec(),
        ..Default::default()
    };
    resp.headers
        .insert("content-type".to_string(), "text/plain".to_string());
    resp.trailers
        .insert("x-trailer".to_string(), "v".to_string());

    let frames = encode_http2_response_frames(&mut encoder, stream_id, &resp).expect("encode");
    assert_eq!(frames.len(), 3);

    assert_eq!(frames[0].header.frame_type, FrameType::Headers);
    assert_eq!(frames[0].header.flags & 0x4, 0x4); // END_HEADERS
    assert_eq!(frames[0].header.flags & 0x1, 0x0); // no END_STREAM

    assert_eq!(frames[1].header.frame_type, FrameType::Data);
    assert_eq!(frames[1].header.flags & 0x1, 0x0); // no END_STREAM

    assert_eq!(frames[2].header.frame_type, FrameType::Headers);
    assert_eq!(frames[2].header.flags & 0x4, 0x4); // END_HEADERS
    assert_eq!(frames[2].header.flags & 0x1, 0x1); // END_STREAM

    let FramePayload::Headers(trailer_block) = &frames[2].payload else {
        panic!("expected trailing HEADERS payload");
    };
    let mut decoder = new_decoder();
    let fields = decode_header_block(
        &mut decoder,
        HeaderBlockInput {
            first_fragment: trailer_block,
            continuation_fragments: &[],
        },
    )
    .expect("decode");
    assert_eq!(fields.len(), 1);
    assert_eq!(fields[0].name, "x-trailer");
    assert_eq!(fields[0].value, "v");
}

#[test]
fn large_body_with_trailers_splits_data_without_end_stream_and_ends_on_trailers() {
    let mut encoder = new_encoder();
    let stream_id = StreamId::new(1).unwrap();
    let body: Vec<u8> = (0..40_000).map(|i| (i % 251) as u8).collect();

    let mut resp = HttpResponse {
        status: Some(200),
        body: body.clone(),
        ..Default::default()
    };
    resp.trailers
        .insert("x-trailer".to_string(), "v".to_string());

    let frames = encode_http2_response_frames(&mut encoder, stream_id, &resp).expect("encode");
    assert_eq!(frames.len(), 5);
    assert_eq!(frames[0].header.frame_type, FrameType::Headers);

    let mut reassembled = Vec::new();
    for frame in &frames[1..4] {
        assert_eq!(frame.header.frame_type, FrameType::Data);
        assert!(frame.header.length <= 16_384);
        assert_eq!(
            frame.header.flags & 0x1,
            0x0,
            "DATA must not end stream when trailers are present"
        );

        let FramePayload::Data(bytes) = &frame.payload else {
            panic!("expected DATA payload");
        };
        assert_eq!(frame.header.length as usize, bytes.len());
        reassembled.extend_from_slice(bytes);
    }
    assert_eq!(reassembled, body);

    assert_eq!(frames[4].header.frame_type, FrameType::Headers);
    assert_eq!(frames[4].header.flags & 0x4, 0x4);
    assert_eq!(frames[4].header.flags & 0x1, 0x1);
}

#[test]
fn headers_without_body_and_with_trailers_emit_two_headers_frames_and_end_on_trailers() {
    let mut encoder = new_encoder();
    let stream_id = StreamId::new(1).unwrap();

    let mut resp = HttpResponse {
        status: Some(200),
        ..Default::default()
    };
    resp.trailers
        .insert("x-trailer".to_string(), "v".to_string());

    let frames = encode_http2_response_frames(&mut encoder, stream_id, &resp).expect("encode");
    assert_eq!(frames.len(), 2);
    assert_eq!(frames[0].header.frame_type, FrameType::Headers);
    assert_eq!(frames[0].header.flags & 0x1, 0x0); // no END_STREAM
    assert_eq!(frames[1].header.frame_type, FrameType::Headers);
    assert_eq!(frames[1].header.flags & 0x1, 0x1); // END_STREAM
}

#[test]
fn invalid_trailer_is_invalid_protocol_data() {
    let mut encoder = new_encoder();
    let stream_id = StreamId::new(1).unwrap();

    let mut resp = HttpResponse {
        status: Some(200),
        body: b"abc".to_vec(),
        ..Default::default()
    };
    resp.trailers
        .insert("connection".to_string(), "x".to_string());
    let err = encode_http2_response_frames(&mut encoder, stream_id, &resp).expect_err("err");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);

    let mut resp2 = HttpResponse {
        status: Some(200),
        ..Default::default()
    };
    resp2.trailers.insert(":path".to_string(), "/".to_string());
    let err = encode_http2_response_frames(&mut encoder, stream_id, &resp2).expect_err("err");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
}
