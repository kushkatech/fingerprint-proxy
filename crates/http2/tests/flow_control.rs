use fingerprint_proxy_http2::{
    FlowControlError, FlowController, StreamId, DEFAULT_WINDOW_SIZE, MAX_WINDOW_SIZE,
};

fn sid(v: u32) -> StreamId {
    StreamId::new(v).expect("valid stream id")
}

#[test]
fn defaults_match_http2_initial_window() {
    let fc = FlowController::default();
    assert_eq!(fc.connection_window(), DEFAULT_WINDOW_SIZE as i64);
    assert_eq!(fc.initial_stream_window(), DEFAULT_WINDOW_SIZE as i64);
}

#[test]
fn consume_data_decrements_connection_and_stream_windows() {
    let mut fc = FlowController::default();
    fc.open_stream(sid(1)).expect("open stream");
    fc.consume_data(sid(1), 1_024).expect("consume");

    assert_eq!(fc.connection_window(), DEFAULT_WINDOW_SIZE as i64 - 1_024);
    assert_eq!(
        fc.stream_window(sid(1)),
        Some(DEFAULT_WINDOW_SIZE as i64 - 1_024)
    );
}

#[test]
fn consume_data_requires_known_stream() {
    let mut fc = FlowController::default();
    let err = fc.consume_data(sid(1), 1).unwrap_err();
    assert_eq!(err, FlowControlError::UnknownStream(sid(1)));
}

#[test]
fn consume_data_errors_when_stream_window_is_insufficient() {
    let mut fc = FlowController::new(5_000, 100).expect("init");
    fc.open_stream(sid(1)).expect("open");

    let err = fc.consume_data(sid(1), 101).unwrap_err();
    assert_eq!(
        err,
        FlowControlError::InsufficientStreamWindow {
            stream_id: sid(1),
            available: 100,
            requested: 101,
        }
    );
}

#[test]
fn consume_data_errors_when_connection_window_is_insufficient() {
    let mut fc = FlowController::new(10, 1_000).expect("init");
    fc.open_stream(sid(1)).expect("open");

    let err = fc.consume_data(sid(1), 11).unwrap_err();
    assert_eq!(
        err,
        FlowControlError::InsufficientConnectionWindow {
            available: 10,
            requested: 11,
        }
    );
}

#[test]
fn window_update_requires_non_zero_increment() {
    let mut fc = FlowController::default();
    let err = fc.apply_connection_window_update(0).unwrap_err();
    assert_eq!(err, FlowControlError::InvalidWindowIncrement(0));
}

#[test]
fn stream_window_update_rejects_overflow() {
    let mut fc = FlowController::new(1_000, MAX_WINDOW_SIZE).expect("init");
    fc.open_stream(sid(1)).expect("open");

    let err = fc.apply_stream_window_update(sid(1), 1).unwrap_err();
    assert_eq!(
        err,
        FlowControlError::WindowOverflow {
            current: MAX_WINDOW_SIZE as i64,
            delta: 1,
        }
    );
}

#[test]
fn updating_initial_stream_window_applies_delta_to_open_streams() {
    let mut fc = FlowController::new(DEFAULT_WINDOW_SIZE, 100).expect("init");
    fc.open_stream(sid(1)).expect("open");
    fc.open_stream(sid(3)).expect("open");
    fc.consume_data(sid(1), 40).expect("consume");

    fc.set_initial_stream_window_size(200)
        .expect("update initial window");

    assert_eq!(fc.initial_stream_window(), 200);
    assert_eq!(fc.stream_window(sid(1)), Some(160));
    assert_eq!(fc.stream_window(sid(3)), Some(200));
}

#[test]
fn set_initial_stream_window_can_make_stream_window_negative() {
    let mut fc = FlowController::new(DEFAULT_WINDOW_SIZE, DEFAULT_WINDOW_SIZE).expect("init");
    fc.open_stream(sid(1)).expect("open");
    fc.consume_data(sid(1), DEFAULT_WINDOW_SIZE)
        .expect("consume full window");

    fc.set_initial_stream_window_size(0)
        .expect("set initial window");
    assert_eq!(
        fc.stream_window(sid(1)),
        Some(-(DEFAULT_WINDOW_SIZE as i64))
    );
}

#[test]
fn connection_stream_id_is_invalid_for_stream_operations() {
    let mut fc = FlowController::default();
    let err = fc.open_stream(StreamId::connection()).unwrap_err();
    assert_eq!(
        err,
        FlowControlError::InvalidStreamId(StreamId::connection())
    );
}
