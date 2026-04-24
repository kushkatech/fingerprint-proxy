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
    conn.receive_frame(&data).expect("consume data");
    assert_eq!(
        conn.flow_control().connection_window(),
        DEFAULT_WINDOW_SIZE as i64 - 1_024
    );
    assert_eq!(
        conn.flow_control().stream_window(sid(1)),
        Some(DEFAULT_WINDOW_SIZE as i64 - 1_024)
    );
    assert_eq!(
        conn.stream_state(sid(1)),
        Some(StreamState::HalfClosedRemote)
    );
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
