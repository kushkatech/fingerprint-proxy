use fingerprint_proxy_http2::{
    ConnectionErrorKind, ConnectionEvent, ConnectionOperation, ConnectionPreface, ConnectionState,
    FlowControlError, Frame, FrameHeader, FramePayload, FrameType, Http2Connection, Setting,
    Settings, StreamId, StreamState, DEFAULT_WINDOW_SIZE,
};

fn sid(v: u32) -> StreamId {
    StreamId::new(v).expect("valid stream id")
}

fn frame(
    frame_type: FrameType,
    flags: u8,
    stream_id: StreamId,
    payload: FramePayload,
    length: u32,
) -> Frame {
    Frame {
        header: FrameHeader {
            length,
            frame_type,
            flags,
            stream_id,
        },
        payload,
    }
}

#[test]
fn accepts_preface_and_processes_local_settings_ack() {
    let mut conn = Http2Connection::new();
    assert_eq!(conn.state(), ConnectionState::AwaitingPreface);

    conn.accept_client_preface(ConnectionPreface::CLIENT_BYTES)
        .expect("accept preface");
    assert_eq!(conn.state(), ConnectionState::Active);

    conn.queue_local_settings().expect("queue local settings");
    assert!(conn.has_pending_local_settings_ack());

    let settings_ack = frame(
        FrameType::Settings,
        0x1,
        StreamId::connection(),
        FramePayload::Settings {
            ack: true,
            settings: Settings::new(Vec::new()),
        },
        0,
    );
    let event = conn
        .receive_frame(&settings_ack)
        .expect("receive settings ack");
    assert_eq!(event, ConnectionEvent::None);
    assert!(!conn.has_pending_local_settings_ack());
}

#[test]
fn rejects_invalid_or_duplicate_preface() {
    let mut conn = Http2Connection::new();
    let err = conn
        .accept_client_preface(b"not-a-preface")
        .expect_err("must fail");
    assert_eq!(err.kind, ConnectionErrorKind::InvalidPreface);

    conn.accept_client_preface(ConnectionPreface::CLIENT_BYTES)
        .expect("accept preface");
    let err = conn
        .accept_client_preface(ConnectionPreface::CLIENT_BYTES)
        .expect_err("duplicate preface must fail");
    assert_eq!(err.kind, ConnectionErrorKind::DuplicatePreface);
}

#[test]
fn rejects_unexpected_settings_ack() {
    let mut conn = Http2Connection::new();
    conn.accept_client_preface(ConnectionPreface::CLIENT_BYTES)
        .expect("preface");

    let settings_ack = frame(
        FrameType::Settings,
        0x1,
        StreamId::connection(),
        FramePayload::Settings {
            ack: true,
            settings: Settings::new(Vec::new()),
        },
        0,
    );
    let err = conn.receive_frame(&settings_ack).expect_err("must fail");
    assert_eq!(err.operation, ConnectionOperation::ReceiveFrame);
    assert_eq!(err.kind, ConnectionErrorKind::UnexpectedSettingsAck);
}

#[test]
fn remote_settings_update_initial_window_and_require_ack_event() {
    let mut conn = Http2Connection::new();
    conn.accept_client_preface(ConnectionPreface::CLIENT_BYTES)
        .expect("preface");

    let open_stream = frame(
        FrameType::Headers,
        0,
        sid(1),
        FramePayload::Headers(vec![0x82]),
        1,
    );
    conn.receive_frame(&open_stream).expect("open stream");

    let settings = Settings::new(vec![Setting {
        id: 0x4,
        value: DEFAULT_WINDOW_SIZE + 1_000,
    }]);
    let settings_frame = frame(
        FrameType::Settings,
        0,
        StreamId::connection(),
        FramePayload::Settings {
            ack: false,
            settings,
        },
        6,
    );
    let event = conn
        .receive_frame(&settings_frame)
        .expect("settings frame must apply");
    assert_eq!(event, ConnectionEvent::AckSettings);
    assert_eq!(conn.remote_settings_version(), 1);
    assert_eq!(
        conn.flow_control().stream_window(sid(1)),
        Some((DEFAULT_WINDOW_SIZE + 1_000) as i64)
    );
}

#[test]
fn data_requires_known_stream_and_consumes_flow_control() {
    let mut conn = Http2Connection::new();
    conn.accept_client_preface(ConnectionPreface::CLIENT_BYTES)
        .expect("preface");

    let unknown_data = frame(
        FrameType::Data,
        0,
        sid(1),
        FramePayload::Data(vec![1, 2, 3]),
        3,
    );
    let err = conn.receive_frame(&unknown_data).expect_err("must fail");
    assert_eq!(err.kind, ConnectionErrorKind::UnknownStream(sid(1)));

    let open_stream = frame(
        FrameType::Headers,
        0,
        sid(1),
        FramePayload::Headers(vec![0x82]),
        1,
    );
    conn.receive_frame(&open_stream).expect("open stream");

    let data = frame(
        FrameType::Data,
        0x1,
        sid(1),
        FramePayload::Data(vec![0; 1_024]),
        1_024,
    );
    let event = conn.receive_frame(&data).expect("consume data");
    assert_eq!(
        event,
        ConnectionEvent::ReplenishInboundWindow {
            stream_id: sid(1),
            connection_increment: 1_024,
            stream_increment: 1_024,
        }
    );
    assert_eq!(
        conn.flow_control().connection_window(),
        DEFAULT_WINDOW_SIZE as i64
    );
    assert_eq!(
        conn.flow_control().stream_window(sid(1)),
        Some(DEFAULT_WINDOW_SIZE as i64)
    );
    assert_eq!(
        conn.stream_state(sid(1)),
        Some(StreamState::HalfClosedRemote)
    );
}

#[test]
fn data_exceeding_current_window_still_fails_before_replenishment() {
    let mut conn = Http2Connection::new();
    conn.accept_client_preface(ConnectionPreface::CLIENT_BYTES)
        .expect("preface");
    let open_stream = frame(
        FrameType::Headers,
        0,
        sid(1),
        FramePayload::Headers(vec![0x82]),
        1,
    );
    conn.receive_frame(&open_stream).expect("open stream");

    let data = frame(
        FrameType::Data,
        0,
        sid(1),
        FramePayload::Data(vec![0; DEFAULT_WINDOW_SIZE as usize + 1]),
        DEFAULT_WINDOW_SIZE + 1,
    );
    let err = conn.receive_frame(&data).expect_err("must fail");
    assert_eq!(
        err.kind,
        ConnectionErrorKind::FlowControl(FlowControlError::InsufficientConnectionWindow {
            available: DEFAULT_WINDOW_SIZE as i64,
            requested: DEFAULT_WINDOW_SIZE + 1,
        })
    );
}

#[test]
fn new_client_stream_headers_must_use_odd_increasing_ids() {
    let mut conn = Http2Connection::new();
    conn.accept_client_preface(ConnectionPreface::CLIENT_BYTES)
        .expect("preface");

    let even_stream = frame(
        FrameType::Headers,
        0,
        sid(2),
        FramePayload::Headers(vec![0x82]),
        1,
    );
    let err = conn
        .receive_frame(&even_stream)
        .expect_err("even client stream id must fail");
    assert_eq!(
        err.kind,
        ConnectionErrorKind::InvalidClientInitiatedStreamId(sid(2))
    );

    let stream_5 = frame(
        FrameType::Headers,
        0,
        sid(5),
        FramePayload::Headers(vec![0x82]),
        1,
    );
    conn.receive_frame(&stream_5).expect("open stream 5");
    assert_eq!(conn.last_stream_id(), sid(5));

    let lower_new_stream = frame(
        FrameType::Headers,
        0,
        sid(3),
        FramePayload::Headers(vec![0x82]),
        1,
    );
    let err = conn
        .receive_frame(&lower_new_stream)
        .expect_err("lower new stream id must fail");
    assert_eq!(
        err.kind,
        ConnectionErrorKind::NonIncreasingClientStreamId {
            stream_id: sid(3),
            last_stream_id: sid(5),
        }
    );
}

#[test]
fn client_originated_push_promise_is_protocol_invalid() {
    let mut conn = Http2Connection::new();
    conn.accept_client_preface(ConnectionPreface::CLIENT_BYTES)
        .expect("preface");

    let push = frame(
        FrameType::PushPromise,
        0x4,
        sid(1),
        FramePayload::PushPromise(vec![0, 0, 0, 2]),
        4,
    );
    let err = conn
        .receive_frame(&push)
        .expect_err("client PUSH_PROMISE must fail");
    assert_eq!(
        err.kind,
        ConnectionErrorKind::ClientPushPromiseReceived(sid(1))
    );
}

#[test]
fn headers_after_remote_end_stream_are_rejected() {
    let mut conn = Http2Connection::new();
    conn.accept_client_preface(ConnectionPreface::CLIENT_BYTES)
        .expect("preface");

    let complete_stream = frame(
        FrameType::Headers,
        0x1,
        sid(1),
        FramePayload::Headers(vec![0x82]),
        1,
    );
    conn.receive_frame(&complete_stream)
        .expect("complete request stream");
    assert_eq!(
        conn.stream_state(sid(1)),
        Some(StreamState::HalfClosedRemote)
    );

    let reused_stream = frame(
        FrameType::Headers,
        0,
        sid(1),
        FramePayload::Headers(vec![0x82]),
        1,
    );
    let err = conn
        .receive_frame(&reused_stream)
        .expect_err("headers after END_STREAM must fail");
    assert_eq!(err.kind, ConnectionErrorKind::StreamAlreadyClosed(sid(1)));
}

#[test]
fn data_after_remote_end_stream_is_rejected() {
    let mut conn = Http2Connection::new();
    conn.accept_client_preface(ConnectionPreface::CLIENT_BYTES)
        .expect("preface");

    let complete_stream = frame(
        FrameType::Headers,
        0x1,
        sid(1),
        FramePayload::Headers(vec![0x82]),
        1,
    );
    conn.receive_frame(&complete_stream)
        .expect("complete request stream");

    let data_after_end = frame(FrameType::Data, 0, sid(1), FramePayload::Data(vec![1]), 1);
    let err = conn
        .receive_frame(&data_after_end)
        .expect_err("data after END_STREAM must fail");
    assert_eq!(err.kind, ConnectionErrorKind::StreamAlreadyClosed(sid(1)));
}

#[test]
fn window_update_applies_connection_and_stream_windows() {
    let mut conn = Http2Connection::new();
    conn.accept_client_preface(ConnectionPreface::CLIENT_BYTES)
        .expect("preface");
    let open_stream = frame(
        FrameType::Headers,
        0,
        sid(1),
        FramePayload::Headers(vec![0x82]),
        1,
    );
    conn.receive_frame(&open_stream).expect("open stream");

    let conn_update = frame(
        FrameType::WindowUpdate,
        0,
        StreamId::connection(),
        FramePayload::WindowUpdate {
            window_size_increment: 10,
        },
        4,
    );
    conn.receive_frame(&conn_update)
        .expect("connection window update");
    assert_eq!(
        conn.flow_control().connection_window(),
        DEFAULT_WINDOW_SIZE as i64 + 10
    );

    let stream_update = frame(
        FrameType::WindowUpdate,
        0,
        sid(1),
        FramePayload::WindowUpdate {
            window_size_increment: 20,
        },
        4,
    );
    conn.receive_frame(&stream_update)
        .expect("stream window update");
    assert_eq!(
        conn.flow_control().stream_window(sid(1)),
        Some(DEFAULT_WINDOW_SIZE as i64 + 20)
    );
}

#[test]
fn goaway_moves_connection_to_closing() {
    let mut conn = Http2Connection::new();
    conn.accept_client_preface(ConnectionPreface::CLIENT_BYTES)
        .expect("preface");

    let goaway = frame(
        FrameType::GoAway,
        0,
        StreamId::connection(),
        FramePayload::GoAway {
            last_stream_id: sid(3),
            error_code: 0x2,
            debug_data: Vec::new(),
        },
        8,
    );
    let event = conn.receive_frame(&goaway).expect("goaway");
    assert_eq!(
        event,
        ConnectionEvent::GoAwayReceived {
            last_stream_id: sid(3),
            error_code: 0x2,
        }
    );
    assert_eq!(conn.state(), ConnectionState::Closing);
}

#[test]
fn goaway_rejects_new_stream_headers() {
    let mut conn = Http2Connection::new();
    conn.accept_client_preface(ConnectionPreface::CLIENT_BYTES)
        .expect("preface");

    let goaway = frame(
        FrameType::GoAway,
        0,
        StreamId::connection(),
        FramePayload::GoAway {
            last_stream_id: sid(1),
            error_code: 0,
            debug_data: Vec::new(),
        },
        8,
    );
    conn.receive_frame(&goaway).expect("goaway");

    let new_stream = frame(
        FrameType::Headers,
        0,
        sid(3),
        FramePayload::Headers(vec![0x82]),
        1,
    );
    let err = conn
        .receive_frame(&new_stream)
        .expect_err("new stream after GOAWAY must fail");
    assert_eq!(err.from, ConnectionState::Closing);
    assert_eq!(err.kind, ConnectionErrorKind::NewStreamAfterGoAway(sid(3)));
}

#[test]
fn non_ack_ping_requests_ack_event_and_ack_is_consumed() {
    let mut conn = Http2Connection::new();
    conn.accept_client_preface(ConnectionPreface::CLIENT_BYTES)
        .expect("preface");

    let opaque = *b"12345678";
    let ping = frame(
        FrameType::Ping,
        0,
        StreamId::connection(),
        FramePayload::Ping { ack: false, opaque },
        8,
    );
    assert_eq!(
        conn.receive_frame(&ping).expect("ping"),
        ConnectionEvent::PingAck { opaque }
    );

    let ping_ack = frame(
        FrameType::Ping,
        0x1,
        StreamId::connection(),
        FramePayload::Ping { ack: true, opaque },
        8,
    );
    assert_eq!(
        conn.receive_frame(&ping_ack).expect("ping ack"),
        ConnectionEvent::None
    );
}

#[test]
fn settings_invalid_window_maps_to_flow_control_error() {
    let mut conn = Http2Connection::new();
    conn.accept_client_preface(ConnectionPreface::CLIENT_BYTES)
        .expect("preface");

    let settings = Settings::new(vec![Setting {
        id: 0x4,
        value: 0x8000_0000,
    }]);
    let settings_frame = frame(
        FrameType::Settings,
        0,
        StreamId::connection(),
        FramePayload::Settings {
            ack: false,
            settings,
        },
        6,
    );

    let err = conn.receive_frame(&settings_frame).expect_err("must fail");
    assert_eq!(
        err.kind,
        ConnectionErrorKind::FlowControl(FlowControlError::InvalidWindowSize(0x8000_0000))
    );
}
