use fingerprint_proxy_quic::{parse_frame, parse_frames, QuicFrame, QuicFrameError};

#[test]
fn parses_padding_ping_crypto_and_stream_frames() {
    let frames = parse_frames(&[
        0x00, // padding
        0x01, // ping
        0x06, 0x00, 0x03, b'a', b'b', b'c', // crypto offset=0 len=3 data
        0x0f, 0x02, 0x01, 0x02, b'h', b'i', // stream id=2 off=1 len=2 fin
    ])
    .expect("frames");

    assert_eq!(
        frames,
        vec![
            QuicFrame::Padding,
            QuicFrame::Ping,
            QuicFrame::Crypto {
                offset: 0,
                data: b"abc".to_vec()
            },
            QuicFrame::Stream {
                stream_id: 2,
                offset: 1,
                data: b"hi".to_vec(),
                fin: true
            }
        ]
    );
}

#[test]
fn parses_ack_and_connection_close_frames() {
    let (ack, used) =
        parse_frame(&[0x03, 0x05, 0x01, 0x00, 0x05, 0x01, 0x02, 0x03]).expect("ack ecn");
    assert_eq!(used, 8);
    assert!(matches!(
        ack,
        QuicFrame::Ack {
            largest_acknowledged: 5,
            ack_delay: 1,
            ack_range_count: 0,
            first_ack_range: 5,
            ecn_counts: Some(_)
        }
    ));

    let (close, used) = parse_frame(&[0x1c, 0x01, 0x06, 0x03, b'b', b'a', b'd']).expect("close");
    assert_eq!(used, 7);
    assert_eq!(
        close,
        QuicFrame::ConnectionClose {
            error_code: 1,
            frame_type: 6,
            reason_phrase: b"bad".to_vec()
        }
    );
}

#[test]
fn stream_without_length_consumes_remaining_payload() {
    let (frame, used) = parse_frame(&[0x08, 0x09, b'a', b'b', b'c']).expect("stream");
    assert_eq!(used, 5);
    assert_eq!(
        frame,
        QuicFrame::Stream {
            stream_id: 9,
            offset: 0,
            data: b"abc".to_vec(),
            fin: false
        }
    );
}

#[test]
fn rejects_truncated_payload_and_unknown_frame_type() {
    let err = parse_frame(&[0x06, 0x00, 0x04, b'a']).expect_err("truncated crypto");
    assert_eq!(err, QuicFrameError::Truncated("crypto data"));

    let err = parse_frame(&[0x20]).expect_err("unknown");
    assert_eq!(err, QuicFrameError::UnknownFrameType(0x20));
}
