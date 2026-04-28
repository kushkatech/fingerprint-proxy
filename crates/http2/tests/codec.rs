use fingerprint_proxy_http2::frames::{
    parse_frame, parse_frame_header, parse_push_promise_promised_stream_id, serialize_frame,
    serialize_frame_header, Frame, FrameHeader, FramePayload, FrameType, Http2FrameError,
};
use fingerprint_proxy_http2::settings::{Setting, Settings};
use fingerprint_proxy_http2::streams::StreamId;

fn sid(v: u32) -> StreamId {
    StreamId::new(v).expect("valid stream id")
}

#[test]
fn frame_header_round_trip() {
    let header = FrameHeader {
        length: 0,
        frame_type: FrameType::Ping,
        flags: 0xA5,
        stream_id: StreamId::connection(),
    };
    let bytes = serialize_frame_header(&header).expect("serialize header");
    let parsed = parse_frame_header(&bytes).expect("parse header");
    assert_eq!(parsed, header);
}

#[test]
fn frame_header_rejects_reserved_bit_in_stream_id() {
    let mut bytes = [0u8; 9];
    bytes[3] = FrameType::Ping.as_u8();
    bytes[5] = 0x80;
    let err = parse_frame_header(&bytes).unwrap_err();
    assert_eq!(err, Http2FrameError::ReservedBitSetInStreamId);
}

#[test]
fn header_length_out_of_range_errors_on_serialize() {
    let header = FrameHeader {
        length: 0x01_00_00_00,
        frame_type: FrameType::Ping,
        flags: 0,
        stream_id: StreamId::connection(),
    };
    let err = serialize_frame_header(&header).unwrap_err();
    assert_eq!(err, Http2FrameError::LengthOutOfRange(0x01_00_00_00));
}

#[test]
fn settings_encode_decode_round_trip() {
    let settings = Settings::new(vec![
        Setting {
            id: 0x1,
            value: 0x2,
        },
        Setting {
            id: 0xABCD,
            value: 0x1234_5678,
        },
    ]);
    let payload = FramePayload::Settings {
        ack: false,
        settings: settings.clone(),
    };
    let bytes_payload = settings.encode();
    let frame = Frame {
        header: FrameHeader {
            length: bytes_payload.len() as u32,
            frame_type: FrameType::Settings,
            flags: 0,
            stream_id: StreamId::connection(),
        },
        payload,
    };

    let encoded = serialize_frame(&frame).expect("serialize frame");
    let (decoded, used) = parse_frame(&encoded).expect("parse frame");
    assert_eq!(used, encoded.len());
    assert_eq!(decoded, frame);
}

#[test]
fn settings_ack_requires_empty_payload() {
    let header = FrameHeader {
        length: 6,
        frame_type: FrameType::Settings,
        flags: 0x1,
        stream_id: StreamId::connection(),
    };
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&serialize_frame_header(&header).expect("serialize header"));
    bytes.extend_from_slice(&[0, 1, 0, 0, 0, 1]);

    let err = parse_frame(&bytes).unwrap_err();
    assert_eq!(err, Http2FrameError::InvalidSettingsAckPayload);
}

#[test]
fn ping_requires_length_8() {
    let header = FrameHeader {
        length: 7,
        frame_type: FrameType::Ping,
        flags: 0,
        stream_id: StreamId::connection(),
    };
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&serialize_frame_header(&header).expect("serialize header"));
    bytes.extend_from_slice(&[0u8; 7]);

    let err = parse_frame(&bytes).unwrap_err();
    assert_eq!(err, Http2FrameError::InvalidPingPayloadLength { actual: 7 });
}

#[test]
fn goaway_encode_decode_with_debug_data() {
    let payload = FramePayload::GoAway {
        last_stream_id: sid(3),
        error_code: 0xDEAD_BEEF,
        debug_data: vec![1, 2, 3],
    };
    let payload_len = 8 + 3;
    let frame = Frame {
        header: FrameHeader {
            length: payload_len,
            frame_type: FrameType::GoAway,
            flags: 0,
            stream_id: StreamId::connection(),
        },
        payload,
    };

    let encoded = serialize_frame(&frame).expect("serialize frame");
    let (decoded, used) = parse_frame(&encoded).expect("parse frame");
    assert_eq!(used, encoded.len());
    assert_eq!(decoded, frame);
}

#[test]
fn goaway_requires_minimum_length() {
    let header = FrameHeader {
        length: 7,
        frame_type: FrameType::GoAway,
        flags: 0,
        stream_id: StreamId::connection(),
    };
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&serialize_frame_header(&header).expect("serialize header"));
    bytes.extend_from_slice(&[0u8; 7]);

    let err = parse_frame(&bytes).unwrap_err();
    assert_eq!(
        err,
        Http2FrameError::InvalidGoAwayPayloadLength { actual: 7 }
    );
}

#[test]
fn window_update_rejects_reserved_bit() {
    let header = FrameHeader {
        length: 4,
        frame_type: FrameType::WindowUpdate,
        flags: 0,
        stream_id: sid(1),
    };
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&serialize_frame_header(&header).expect("serialize header"));
    bytes.extend_from_slice(&0x8000_0001u32.to_be_bytes());

    let err = parse_frame(&bytes).unwrap_err();
    assert_eq!(err, Http2FrameError::ReservedBitSetInWindowUpdate);
}

#[test]
fn rst_stream_requires_length_4() {
    let header = FrameHeader {
        length: 5,
        frame_type: FrameType::RstStream,
        flags: 0,
        stream_id: sid(1),
    };
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&serialize_frame_header(&header).expect("serialize header"));
    bytes.extend_from_slice(&[0u8; 5]);

    let err = parse_frame(&bytes).unwrap_err();
    assert_eq!(
        err,
        Http2FrameError::InvalidRstStreamPayloadLength { actual: 5 }
    );
}

#[test]
fn push_promise_promised_stream_id_is_parsed_deterministically() {
    let promised = parse_push_promise_promised_stream_id(0x4, &[0, 0, 0, 2, 0x82])
        .expect("parse promised stream id");
    assert_eq!(promised, sid(2));
}

#[test]
fn push_promise_promised_stream_id_rejects_invalid_payload() {
    let err = parse_push_promise_promised_stream_id(0x4, &[0, 0, 0]).expect_err("short payload");
    assert_eq!(
        err,
        Http2FrameError::InvalidPushPromisePayloadLength { actual: 3 }
    );

    let err =
        parse_push_promise_promised_stream_id(0x4, &[0x80, 0, 0, 2]).expect_err("reserved bit");
    assert_eq!(
        err,
        Http2FrameError::ReservedBitSetInPushPromisePromisedStreamId
    );

    let err = parse_push_promise_promised_stream_id(0x4, &[0, 0, 0, 0])
        .expect_err("zero promised stream");
    assert_eq!(err, Http2FrameError::InvalidPushPromisePromisedStreamId);
}

#[test]
fn stream_id_rules_are_enforced() {
    // SETTINGS must use stream_id 0.
    let header = FrameHeader {
        length: 0,
        frame_type: FrameType::Settings,
        flags: 0x1,
        stream_id: sid(1),
    };
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&serialize_frame_header(&header).expect("serialize header"));
    let err = parse_frame(&bytes).unwrap_err();
    assert_eq!(
        err,
        Http2FrameError::InvalidStreamIdForFrameType {
            frame_type: FrameType::Settings,
            stream_id: 1
        }
    );

    // DATA must not use stream_id 0.
    let header = FrameHeader {
        length: 0,
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: StreamId::connection(),
    };
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&serialize_frame_header(&header).expect("serialize header"));
    let err = parse_frame(&bytes).unwrap_err();
    assert_eq!(
        err,
        Http2FrameError::InvalidStreamIdForFrameType {
            frame_type: FrameType::Data,
            stream_id: 0
        }
    );
}

#[test]
fn opaque_headers_payload_round_trip() {
    let payload = vec![0x00, 0xFF, 0x01, 0x02, 0x03];
    let frame = Frame {
        header: FrameHeader {
            length: payload.len() as u32,
            frame_type: FrameType::Headers,
            flags: 0x4,
            stream_id: sid(1),
        },
        payload: FramePayload::Headers(payload),
    };

    let encoded = serialize_frame(&frame).expect("serialize frame");
    let (decoded, used) = parse_frame(&encoded).expect("parse frame");
    assert_eq!(used, encoded.len());
    assert_eq!(decoded, frame);
}

#[test]
fn data_frame_with_padding_is_decoded_without_padding_bytes() {
    let header = FrameHeader {
        length: 7,
        frame_type: FrameType::Data,
        flags: 0x8, // PADDED
        stream_id: sid(1),
    };
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&serialize_frame_header(&header).expect("serialize header"));
    bytes.extend_from_slice(&[2, b'a', b'b', b'c', b'd', 0, 0]); // pad len + data + padding

    let (decoded, used) = parse_frame(&bytes).expect("parse");
    assert_eq!(used, bytes.len());
    assert_eq!(decoded.header, header);
    assert_eq!(decoded.payload, FramePayload::Data(b"abcd".to_vec()));
}

#[test]
fn data_frame_with_invalid_padding_is_rejected() {
    let header = FrameHeader {
        length: 4,
        frame_type: FrameType::Data,
        flags: 0x8, // PADDED
        stream_id: sid(1),
    };
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&serialize_frame_header(&header).expect("serialize header"));
    bytes.extend_from_slice(&[4, b'a', b'b', b'c']); // pad len exceeds payload-1

    let err = parse_frame(&bytes).unwrap_err();
    assert_eq!(
        err,
        Http2FrameError::InvalidDataPadding {
            pad_length: 4,
            payload_length: 4
        }
    );
}

#[test]
fn serialize_data_frame_rejects_padded_flag_without_padding_metadata() {
    let frame = Frame {
        header: FrameHeader {
            length: 3,
            frame_type: FrameType::Data,
            flags: 0x8, // PADDED
            stream_id: sid(1),
        },
        payload: FramePayload::Data(b"abc".to_vec()),
    };

    let err = serialize_frame(&frame).unwrap_err();
    assert_eq!(err, Http2FrameError::UnsupportedDataPaddingOnSerialize);
}
