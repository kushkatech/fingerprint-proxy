use fingerprint_proxy_core::error::ErrorKind;
use fingerprint_proxy_hpack::HeaderField as HpackHeaderField;
use fingerprint_proxy_http2::{
    parse_frame, parse_frame_header, serialize_frame, Frame, FrameHeader, FramePayload, FrameType,
    Setting, Settings, StreamId,
};
use fingerprint_proxy_upstream::http2_session::{
    Http2ResponseEvent, Http2SharedSession, Http2SharedSessionConfig,
};
use std::io;
use std::time::Duration;
use tokio::io::{duplex, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

const FLAG_ACK: u8 = 0x1;
const FLAG_END_STREAM: u8 = 0x1;
const FLAG_END_HEADERS: u8 = 0x4;

#[tokio::test]
async fn concurrent_leases_share_session_and_route_out_of_order_responses() {
    let (client_io, mut server_io) = duplex(4096);
    let (session, owner) = Http2SharedSession::spawn(
        client_io,
        Http2SharedSessionConfig::new(2, 8, 4).expect("config"),
    )
    .expect("spawn session");

    let mut lease_one = session.lease_stream().await.expect("lease one");
    let mut lease_two = session.lease_stream().await.expect("lease two");
    assert_eq!(lease_one.stream_id().as_u32(), 1);
    assert_eq!(lease_two.stream_id().as_u32(), 3);

    lease_one
        .submit_frame(headers_frame(lease_one.stream_id(), b"request-one", true))
        .await
        .expect("send request one");
    lease_two
        .submit_frame(headers_frame(lease_two.stream_id(), b"request-two", true))
        .await
        .expect("send request two");

    let upstream_request_one = read_test_frame(&mut server_io).await.expect("request one");
    let upstream_request_two = read_test_frame(&mut server_io).await.expect("request two");
    assert_eq!(upstream_request_one.header.stream_id, lease_one.stream_id());
    assert_eq!(upstream_request_two.header.stream_id, lease_two.stream_id());

    write_test_frame(
        &mut server_io,
        &response_headers_frame(lease_two.stream_id(), "response-two", true),
    )
    .await
    .expect("write response two");
    write_test_frame(
        &mut server_io,
        &response_headers_frame(lease_one.stream_id(), "response-one", true),
    )
    .await
    .expect("write response one");

    let response_two = lease_two
        .recv_response_event()
        .await
        .expect("response two")
        .expect("response two ok");
    let response_one = lease_one
        .recv_response_event()
        .await
        .expect("response one")
        .expect("response one ok");
    assert_response_header_value(&response_two, "x-test", "response-two", true);
    assert_response_header_value(&response_one, "x-test", "response-one", true);

    drop(session);
    drop(server_io);
    owner.await.expect("owner task");
}

#[tokio::test]
async fn stream_capacity_limit_rejects_deterministically() {
    let (client_io, server_io) = duplex(4096);
    let (session, owner) = Http2SharedSession::spawn(
        client_io,
        Http2SharedSessionConfig::new(1, 8, 4).expect("config"),
    )
    .expect("spawn session");

    let _lease = session.lease_stream().await.expect("first lease");
    let err = match session.lease_stream().await {
        Ok(_) => panic!("second lease must be rejected"),
        Err(err) => err,
    };
    assert_eq!(err.kind, ErrorKind::ValidationFailed);
    assert_eq!(
        err.message,
        "HTTP/2 shared session stream capacity exhausted"
    );

    drop(session);
    drop(server_io);
    owner.await.expect("owner task");
}

#[tokio::test]
async fn goaway_drains_wire_initiated_streams_and_rejects_new_leases() {
    let (client_io, mut server_io) = duplex(4096);
    let (session, owner) = Http2SharedSession::spawn(
        client_io,
        Http2SharedSessionConfig::new(4, 8, 4).expect("config"),
    )
    .expect("spawn session");

    let mut initiated_lease = session.lease_stream().await.expect("initiated lease");
    let mut unsubmitted_lease = session.lease_stream().await.expect("unsubmitted lease");
    let mut above_last_lease = session.lease_stream().await.expect("above-last lease");

    initiated_lease
        .submit_frame(headers_frame(
            initiated_lease.stream_id(),
            b"initiated-request",
            true,
        ))
        .await
        .expect("initiated stream can submit before GOAWAY");
    let upstream_request = read_test_frame(&mut server_io)
        .await
        .expect("initiated upstream request");
    assert_eq!(
        upstream_request.header.stream_id,
        initiated_lease.stream_id()
    );

    write_test_frame(
        &mut server_io,
        &goaway_frame(unsubmitted_lease.stream_id(), 0),
    )
    .await
    .expect("goaway");

    let unsubmitted_err = unsubmitted_lease
        .recv_response_event()
        .await
        .expect("unsubmitted lease failure")
        .expect_err("unsubmitted lease must fail");
    assert_eq!(unsubmitted_err.kind, ErrorKind::InvalidProtocolData);
    assert_eq!(
        unsubmitted_err.message,
        goaway_rejected_stream_message(
            unsubmitted_lease.stream_id(),
            unsubmitted_lease.stream_id(),
            0
        )
    );

    let above_last_err = above_last_lease
        .recv_response_event()
        .await
        .expect("above-last lease failure")
        .expect_err("above-last lease must fail");
    assert_eq!(above_last_err.kind, ErrorKind::InvalidProtocolData);
    assert_eq!(
        above_last_err.message,
        goaway_rejected_stream_message(
            above_last_lease.stream_id(),
            unsubmitted_lease.stream_id(),
            0
        )
    );

    let post_goaway = match session.lease_stream().await {
        Ok(_) => panic!("session must reject new leases after GOAWAY"),
        Err(err) => err,
    };
    assert_eq!(post_goaway.message, "HTTP/2 shared session is closed");

    write_test_frame(
        &mut server_io,
        &response_headers_frame(initiated_lease.stream_id(), "initiated-response", true),
    )
    .await
    .expect("initiated response");
    let response = initiated_lease
        .recv_response_event()
        .await
        .expect("initiated response")
        .expect("initiated response ok");
    assert_response_header_value(&response, "x-test", "initiated-response", true);

    drop(session);
    drop(server_io);
    owner.await.expect("owner task");
}

#[tokio::test]
async fn goaway_rejected_stream_submits_fail_with_session_draining_error() {
    let (client_io, mut server_io) = duplex(4096);
    let (session, owner) = Http2SharedSession::spawn(
        client_io,
        Http2SharedSessionConfig::new(3, 8, 4).expect("config"),
    )
    .expect("spawn session");

    let initiated_lease = session.lease_stream().await.expect("initiated lease");
    let mut rejected_lease = session.lease_stream().await.expect("rejected lease");

    initiated_lease
        .submit_frame(headers_frame(
            initiated_lease.stream_id(),
            b"initiated-request",
            true,
        ))
        .await
        .expect("initiated stream can submit before GOAWAY");
    let upstream_request = read_test_frame(&mut server_io)
        .await
        .expect("initiated upstream request");
    assert_eq!(
        upstream_request.header.stream_id,
        initiated_lease.stream_id()
    );

    write_test_frame(&mut server_io, &goaway_frame(rejected_lease.stream_id(), 7))
        .await
        .expect("goaway");
    let rejected_err = rejected_lease
        .recv_response_event()
        .await
        .expect("rejected lease failure")
        .expect_err("rejected lease must fail");
    let expected =
        goaway_rejected_stream_message(rejected_lease.stream_id(), rejected_lease.stream_id(), 7);
    assert_eq!(rejected_err.message, expected);

    let submit_err = rejected_lease
        .submit_frame(headers_frame(
            rejected_lease.stream_id(),
            b"late-rejected-request",
            true,
        ))
        .await
        .expect_err("rejected stream submit must fail");
    assert_eq!(submit_err.kind, ErrorKind::InvalidProtocolData);
    assert_eq!(submit_err.message, expected);

    drop(session);
    drop(server_io);
    owner.await.expect("owner task");
}

#[tokio::test]
async fn goaway_resolves_pending_outbound_data_for_rejected_stream() {
    let (client_io, mut server_io) = duplex(4096);
    let (session, owner) = Http2SharedSession::spawn(
        client_io,
        Http2SharedSessionConfig::new(3, 8, 4).expect("config"),
    )
    .expect("spawn session");

    write_test_frame(&mut server_io, &settings_initial_window_size_frame(0))
        .await
        .expect("zero initial window");
    assert_settings_ack(&mut server_io).await;

    let initiated_lease = session.lease_stream().await.expect("initiated lease");
    let mut rejected_lease = session.lease_stream().await.expect("rejected lease");
    let initiated_stream_id = initiated_lease.stream_id();
    let rejected_stream_id = rejected_lease.stream_id();

    initiated_lease
        .submit_frame(headers_frame(
            initiated_stream_id,
            b"initiated-request",
            true,
        ))
        .await
        .expect("initiated stream can submit before GOAWAY");
    let upstream_request = read_test_frame(&mut server_io)
        .await
        .expect("initiated upstream request");
    assert_eq!(upstream_request.header.stream_id, initiated_stream_id);

    let expected = goaway_rejected_stream_message(rejected_stream_id, rejected_stream_id, 0);
    {
        let submit =
            rejected_lease.submit_frame(data_frame(rejected_stream_id, b"blocked".to_vec(), true));
        tokio::pin!(submit);

        assert!(
            timeout(Duration::from_millis(100), &mut submit)
                .await
                .is_err(),
            "submit reply must remain pending while DATA is flow-control blocked"
        );

        write_test_frame(&mut server_io, &goaway_frame(rejected_stream_id, 0))
            .await
            .expect("goaway");
        let submit_err = submit.await.expect_err("pending DATA submit must fail");
        assert_eq!(submit_err.kind, ErrorKind::InvalidProtocolData);
        assert_eq!(submit_err.message, expected);
    }

    let rejected_err = rejected_lease
        .recv_response_event()
        .await
        .expect("rejected lease failure")
        .expect_err("rejected lease must fail");
    assert_eq!(rejected_err.message, expected);

    drop(session);
    drop(server_io);
    owner.await.expect("owner task");
}

#[tokio::test]
async fn settings_and_ping_are_acked_by_owner_task() {
    let (client_io, mut server_io) = duplex(4096);
    let (_session, owner) = Http2SharedSession::spawn(
        client_io,
        Http2SharedSessionConfig::new(2, 8, 4).expect("config"),
    )
    .expect("spawn session");

    write_test_frame(&mut server_io, &settings_frame())
        .await
        .expect("settings");
    let settings_ack = read_test_frame(&mut server_io).await.expect("settings ack");
    assert_eq!(settings_ack.header.frame_type, FrameType::Settings);
    assert_eq!(settings_ack.header.flags & FLAG_ACK, FLAG_ACK);
    assert!(matches!(
        settings_ack.payload,
        FramePayload::Settings {
            ack: true,
            settings: _
        }
    ));

    let opaque = *b"12345678";
    write_test_frame(&mut server_io, &ping_frame(opaque))
        .await
        .expect("ping");
    let ping_ack = read_test_frame(&mut server_io).await.expect("ping ack");
    assert_eq!(ping_ack.header.frame_type, FrameType::Ping);
    assert_eq!(ping_ack.header.flags & FLAG_ACK, FLAG_ACK);
    assert!(matches!(
        ping_ack.payload,
        FramePayload::Ping {
            ack: true,
            opaque: returned
        } if returned == opaque
    ));

    drop(server_io);
    owner.await.expect("owner task");
}

#[tokio::test]
async fn lower_peer_settings_limit_restricts_new_leases() {
    let (client_io, mut server_io) = duplex(4096);
    let (session, owner) = Http2SharedSession::spawn(
        client_io,
        Http2SharedSessionConfig::new(4, 8, 4).expect("config"),
    )
    .expect("spawn session");

    write_test_frame(&mut server_io, &settings_max_concurrent_streams_frame(2))
        .await
        .expect("peer settings");
    assert_settings_ack(&mut server_io).await;

    let _lease_one = session.lease_stream().await.expect("lease one");
    let _lease_two = session.lease_stream().await.expect("lease two");
    let err = match session.lease_stream().await {
        Ok(_) => panic!("third lease must be rejected by peer limit"),
        Err(err) => err,
    };
    assert_eq!(err.kind, ErrorKind::ValidationFailed);
    assert_eq!(
        err.message,
        "HTTP/2 shared session stream capacity exhausted"
    );

    drop(session);
    drop(server_io);
    owner.await.expect("owner task");
}

#[tokio::test]
async fn active_leases_remain_valid_after_lower_peer_limit() {
    let (client_io, mut server_io) = duplex(4096);
    let (session, owner) = Http2SharedSession::spawn(
        client_io,
        Http2SharedSessionConfig::new(4, 8, 4).expect("config"),
    )
    .expect("spawn session");

    let mut lease_one = session.lease_stream().await.expect("lease one");
    let lease_two = session.lease_stream().await.expect("lease two");

    write_test_frame(&mut server_io, &settings_max_concurrent_streams_frame(1))
        .await
        .expect("peer settings");
    assert_settings_ack(&mut server_io).await;

    let err = match session.lease_stream().await {
        Ok(_) => panic!("new lease must be rejected while active streams exceed peer limit"),
        Err(err) => err,
    };
    assert_eq!(err.kind, ErrorKind::ValidationFailed);
    assert_eq!(
        err.message,
        "HTTP/2 shared session stream capacity exhausted"
    );

    lease_one
        .submit_frame(headers_frame(lease_one.stream_id(), b"request-one", true))
        .await
        .expect("active lease one can still submit");
    lease_two
        .submit_frame(headers_frame(lease_two.stream_id(), b"request-two", true))
        .await
        .expect("active lease two can still submit");
    let upstream_request_one = read_test_frame(&mut server_io).await.expect("request one");
    let upstream_request_two = read_test_frame(&mut server_io).await.expect("request two");
    assert_eq!(upstream_request_one.header.stream_id, lease_one.stream_id());
    assert_eq!(upstream_request_two.header.stream_id, lease_two.stream_id());

    write_test_frame(
        &mut server_io,
        &response_headers_frame(lease_one.stream_id(), "response-one", true),
    )
    .await
    .expect("write response one");
    let response_one = lease_one
        .recv_response_event()
        .await
        .expect("response one")
        .expect("response one ok");
    assert_response_header_value(&response_one, "x-test", "response-one", true);

    drop(session);
    drop(server_io);
    owner.await.expect("owner task");
}

#[tokio::test]
async fn raising_peer_settings_limit_allows_later_leases() {
    let (client_io, mut server_io) = duplex(4096);
    let (session, owner) = Http2SharedSession::spawn(
        client_io,
        Http2SharedSessionConfig::new(3, 8, 4).expect("config"),
    )
    .expect("spawn session");

    write_test_frame(&mut server_io, &settings_max_concurrent_streams_frame(1))
        .await
        .expect("lower peer settings");
    assert_settings_ack(&mut server_io).await;

    let _lease_one = session.lease_stream().await.expect("lease one");
    let lower_err = match session.lease_stream().await {
        Ok(_) => panic!("second lease must be rejected by lower peer limit"),
        Err(err) => err,
    };
    assert_eq!(lower_err.kind, ErrorKind::ValidationFailed);

    write_test_frame(&mut server_io, &settings_max_concurrent_streams_frame(2))
        .await
        .expect("raised peer settings");
    assert_settings_ack(&mut server_io).await;

    let lease_two = session.lease_stream().await.expect("lease two after raise");
    assert_eq!(lease_two.stream_id().as_u32(), 3);

    drop(session);
    drop(server_io);
    owner.await.expect("owner task");
}

#[tokio::test]
async fn peer_settings_limit_zero_blocks_new_leases_while_active_stream_completes() {
    let (client_io, mut server_io) = duplex(4096);
    let (session, owner) = Http2SharedSession::spawn(
        client_io,
        Http2SharedSessionConfig::new(2, 8, 4).expect("config"),
    )
    .expect("spawn session");

    let mut active_lease = session.lease_stream().await.expect("active lease");

    write_test_frame(&mut server_io, &settings_max_concurrent_streams_frame(0))
        .await
        .expect("zero peer settings");
    assert_settings_ack(&mut server_io).await;

    let blocked = match session.lease_stream().await {
        Ok(_) => panic!("new lease must be blocked by zero peer limit"),
        Err(err) => err,
    };
    assert_eq!(blocked.kind, ErrorKind::ValidationFailed);
    assert_eq!(
        blocked.message,
        "HTTP/2 shared session stream capacity exhausted"
    );

    active_lease
        .submit_frame(headers_frame(
            active_lease.stream_id(),
            b"active-request",
            true,
        ))
        .await
        .expect("active lease can still submit");
    let upstream_request = read_test_frame(&mut server_io)
        .await
        .expect("active request");
    assert_eq!(upstream_request.header.stream_id, active_lease.stream_id());

    write_test_frame(
        &mut server_io,
        &response_headers_frame(active_lease.stream_id(), "active-response", true),
    )
    .await
    .expect("active response");
    let response = active_lease
        .recv_response_event()
        .await
        .expect("active response")
        .expect("active response ok");
    assert_response_header_value(&response, "x-test", "active-response", true);

    let still_blocked = match session.lease_stream().await {
        Ok(_) => panic!("zero peer limit must continue blocking new leases"),
        Err(err) => err,
    };
    assert_eq!(still_blocked.kind, ErrorKind::ValidationFailed);

    drop(session);
    drop(server_io);
    owner.await.expect("owner task");
}

#[tokio::test]
async fn response_hpack_dynamic_table_is_shared_across_streams() {
    let (client_io, mut server_io) = duplex(4096);
    let (session, owner) = Http2SharedSession::spawn(
        client_io,
        Http2SharedSessionConfig::new(2, 8, 4).expect("config"),
    )
    .expect("spawn session");

    let mut lease_one = session.lease_stream().await.expect("lease one");
    let mut lease_two = session.lease_stream().await.expect("lease two");

    let mut encoder =
        fingerprint_proxy_hpack::Encoder::new(fingerprint_proxy_hpack::EncoderConfig {
            max_dynamic_table_size: 4096,
            use_huffman: false,
        });
    let indexed_field = HpackHeaderField {
        name: b"x-shared".to_vec(),
        value: b"alpha".to_vec(),
    };
    let first_block = encoder.encode_literal_with_incremental_indexing(&indexed_field);
    let second_block = encoder.encode_indexed(62);

    write_test_frame(
        &mut server_io,
        &headers_frame_with_flags(lease_one.stream_id(), first_block, FLAG_END_HEADERS),
    )
    .await
    .expect("write first response");
    let first = lease_one
        .recv_response_event()
        .await
        .expect("first response")
        .expect("first response ok");
    assert_response_header_value(&first, "x-shared", "alpha", false);

    write_test_frame(
        &mut server_io,
        &headers_frame_with_flags(
            lease_two.stream_id(),
            second_block,
            FLAG_END_HEADERS | FLAG_END_STREAM,
        ),
    )
    .await
    .expect("write second response");
    let second = lease_two
        .recv_response_event()
        .await
        .expect("second response")
        .expect("second response ok");
    assert_response_header_value(&second, "x-shared", "alpha", true);

    drop(session);
    drop(server_io);
    owner.await.expect("owner task");
}

#[tokio::test]
async fn accepted_response_data_emits_connection_and_stream_window_updates() {
    let (client_io, mut server_io) = duplex(4096);
    let (session, owner) = Http2SharedSession::spawn(
        client_io,
        Http2SharedSessionConfig::new(2, 8, 4).expect("config"),
    )
    .expect("spawn session");

    let mut lease = session.lease_stream().await.expect("lease");
    write_test_frame(
        &mut server_io,
        &data_frame(lease.stream_id(), b"response-body".to_vec(), true),
    )
    .await
    .expect("write data");

    let connection_update = read_test_frame(&mut server_io)
        .await
        .expect("connection window update");
    assert_window_update(&connection_update, StreamId::connection(), 13);
    let stream_update = read_test_frame(&mut server_io)
        .await
        .expect("stream window update");
    assert_window_update(&stream_update, lease.stream_id(), 13);

    let event = lease
        .recv_response_event()
        .await
        .expect("response data")
        .expect("response data ok");
    assert_eq!(
        event,
        Http2ResponseEvent::Data {
            bytes: b"response-body".to_vec(),
            end_stream: true,
        }
    );

    drop(session);
    drop(server_io);
    owner.await.expect("owner task");
}

#[tokio::test]
async fn zero_length_response_data_emits_no_window_update() {
    let (client_io, mut server_io) = duplex(4096);
    let (session, owner) = Http2SharedSession::spawn(
        client_io,
        Http2SharedSessionConfig::new(2, 8, 4).expect("config"),
    )
    .expect("spawn session");

    let mut lease = session.lease_stream().await.expect("lease");
    write_test_frame(
        &mut server_io,
        &data_frame(lease.stream_id(), Vec::new(), true),
    )
    .await
    .expect("write empty data");

    let event = lease
        .recv_response_event()
        .await
        .expect("empty data")
        .expect("empty data ok");
    assert_eq!(
        event,
        Http2ResponseEvent::Data {
            bytes: Vec::new(),
            end_stream: true,
        }
    );
    assert!(
        timeout(Duration::from_millis(100), read_test_frame(&mut server_io))
            .await
            .is_err(),
        "zero-length DATA must not emit WINDOW_UPDATE"
    );

    drop(session);
    drop(server_io);
    owner.await.expect("owner task");
}

#[tokio::test]
async fn oversized_response_data_fails_without_routing_successful_data() {
    let (client_io, mut server_io) = duplex(131_072);
    let (session, owner) = Http2SharedSession::spawn(
        client_io,
        Http2SharedSessionConfig::new(2, 8, 4).expect("config"),
    )
    .expect("spawn session");

    let mut lease = session.lease_stream().await.expect("lease");
    write_test_frame(
        &mut server_io,
        &data_frame(lease.stream_id(), vec![0; 65_536], false),
    )
    .await
    .expect("write oversized data");

    let err = lease
        .recv_response_event()
        .await
        .expect("flow-control failure")
        .expect_err("oversized data must fail");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
    assert!(err.message.contains("inbound flow-control error"));
    assert!(err.message.contains("insufficient connection window"));
    match timeout(Duration::from_millis(100), read_test_frame(&mut server_io)).await {
        Err(_) => {}
        Ok(Err(err)) if err.kind() == io::ErrorKind::UnexpectedEof => {}
        Ok(Err(err)) => panic!("unexpected read error: {err}"),
        Ok(Ok(frame)) => panic!("rejected oversized DATA emitted frame: {frame:?}"),
    }

    drop(session);
    drop(server_io);
    owner.await.expect("owner task");
}

#[tokio::test]
async fn response_data_after_end_stream_fails_before_window_update_or_success_event() {
    let (client_io, mut server_io) = duplex(4096);
    let (session, owner) = Http2SharedSession::spawn(
        client_io,
        Http2SharedSessionConfig::new(2, 8, 4).expect("config"),
    )
    .expect("spawn session");

    let mut completed_lease = session.lease_stream().await.expect("completed lease");
    let mut witness_lease = session.lease_stream().await.expect("witness lease");
    write_test_frame(
        &mut server_io,
        &data_frame(completed_lease.stream_id(), b"done".to_vec(), true),
    )
    .await
    .expect("write completing data");

    let connection_update = read_test_frame(&mut server_io)
        .await
        .expect("connection window update");
    assert_window_update(&connection_update, StreamId::connection(), 4);
    let stream_update = read_test_frame(&mut server_io)
        .await
        .expect("stream window update");
    assert_window_update(&stream_update, completed_lease.stream_id(), 4);

    let event = completed_lease
        .recv_response_event()
        .await
        .expect("completed data")
        .expect("completed data ok");
    assert_eq!(
        event,
        Http2ResponseEvent::Data {
            bytes: b"done".to_vec(),
            end_stream: true,
        }
    );

    write_test_frame(
        &mut server_io,
        &data_frame(completed_lease.stream_id(), b"late".to_vec(), false),
    )
    .await
    .expect("write late data");

    let err = witness_lease
        .recv_response_event()
        .await
        .expect("session failure")
        .expect_err("late data must fail the session");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
    assert_eq!(
        err.message,
        "HTTP/2 shared session received DATA for a non-active stream"
    );
    assert!(
        completed_lease.recv_response_event().await.is_none(),
        "completed stream must not receive a successful late DATA event"
    );
    match timeout(Duration::from_millis(100), read_test_frame(&mut server_io)).await {
        Err(_) => {}
        Ok(Err(err)) if err.kind() == io::ErrorKind::UnexpectedEof => {}
        Ok(Err(err)) => panic!("unexpected read error: {err}"),
        Ok(Ok(frame)) => panic!("late DATA emitted WINDOW_UPDATE/frame: {frame:?}"),
    }

    drop(session);
    drop(server_io);
    owner.await.expect("owner task");
}

#[tokio::test]
async fn outbound_request_data_within_peer_windows_writes_immediately() {
    let (client_io, mut server_io) = duplex(4096);
    let (session, owner) = Http2SharedSession::spawn(
        client_io,
        Http2SharedSessionConfig::new(2, 8, 4).expect("config"),
    )
    .expect("spawn session");

    let lease = session.lease_stream().await.expect("lease");
    lease
        .submit_frame(data_frame(
            lease.stream_id(),
            b"request-body".to_vec(),
            true,
        ))
        .await
        .expect("send request data");

    let upstream_data = read_test_frame(&mut server_io)
        .await
        .expect("upstream data");
    assert_eq!(upstream_data.header.stream_id, lease.stream_id());
    assert_eq!(
        upstream_data.payload,
        FramePayload::Data(b"request-body".to_vec())
    );
    assert_eq!(
        upstream_data.header.flags & FLAG_END_STREAM,
        FLAG_END_STREAM
    );

    drop(session);
    drop(server_io);
    owner.await.expect("owner task");
}

#[tokio::test]
async fn outbound_request_data_waits_for_connection_and_stream_window_updates() {
    let (client_io, mut server_io) = duplex(131_072);
    let (session, owner) = Http2SharedSession::spawn(
        client_io,
        Http2SharedSessionConfig::new(2, 8, 4).expect("config"),
    )
    .expect("spawn session");

    let lease = session.lease_stream().await.expect("lease");
    let body = vec![7; 65_536];
    let submit = lease.submit_frame(data_frame(lease.stream_id(), body.clone(), true));
    tokio::pin!(submit);

    assert!(
        timeout(Duration::from_millis(100), &mut submit)
            .await
            .is_err(),
        "submit reply must remain pending while DATA is flow-control blocked"
    );
    assert!(
        timeout(Duration::from_millis(100), read_test_frame(&mut server_io))
            .await
            .is_err(),
        "DATA larger than the initial peer window must not be written immediately"
    );

    write_test_frame(
        &mut server_io,
        &window_update_frame(StreamId::connection(), 1),
    )
    .await
    .expect("connection window update");
    assert!(
        timeout(Duration::from_millis(100), read_test_frame(&mut server_io))
            .await
            .is_err(),
        "connection WINDOW_UPDATE alone must not release a stream-window-blocked DATA frame"
    );

    write_test_frame(&mut server_io, &window_update_frame(lease.stream_id(), 1))
        .await
        .expect("stream window update");
    let upstream_data = read_test_frame(&mut server_io)
        .await
        .expect("released upstream data");
    assert_eq!(upstream_data.header.stream_id, lease.stream_id());
    assert_eq!(upstream_data.payload, FramePayload::Data(body));
    submit.await.expect("submit completes after window updates");

    drop(session);
    drop(server_io);
    owner.await.expect("owner task");
}

#[tokio::test]
async fn lowered_peer_initial_window_blocks_later_outbound_data_until_window_update() {
    let (client_io, mut server_io) = duplex(4096);
    let (session, owner) = Http2SharedSession::spawn(
        client_io,
        Http2SharedSessionConfig::new(2, 8, 4).expect("config"),
    )
    .expect("spawn session");

    write_test_frame(&mut server_io, &settings_initial_window_size_frame(5))
        .await
        .expect("lower initial window");
    assert_settings_ack(&mut server_io).await;

    let lease = session.lease_stream().await.expect("lease");
    let body = b"123456".to_vec();
    let submit = lease.submit_frame(data_frame(lease.stream_id(), body.clone(), true));
    tokio::pin!(submit);

    assert!(
        timeout(Duration::from_millis(100), &mut submit)
            .await
            .is_err(),
        "submit reply must wait for peer stream window"
    );
    assert!(
        timeout(Duration::from_millis(100), read_test_frame(&mut server_io))
            .await
            .is_err(),
        "DATA exceeding lowered peer stream window must be held"
    );

    write_test_frame(&mut server_io, &window_update_frame(lease.stream_id(), 1))
        .await
        .expect("stream window update");
    let upstream_data = read_test_frame(&mut server_io)
        .await
        .expect("released upstream data");
    assert_eq!(upstream_data.header.stream_id, lease.stream_id());
    assert_eq!(upstream_data.payload, FramePayload::Data(body));
    submit.await.expect("submit completes after stream update");

    drop(session);
    drop(server_io);
    owner.await.expect("owner task");
}

#[tokio::test]
async fn pending_outbound_request_data_preserves_same_stream_fifo_order() {
    let (client_io, mut server_io) = duplex(4096);
    let (session, owner) = Http2SharedSession::spawn(
        client_io,
        Http2SharedSessionConfig::new(2, 8, 4).expect("config"),
    )
    .expect("spawn session");

    write_test_frame(&mut server_io, &settings_initial_window_size_frame(5))
        .await
        .expect("lower initial window");
    assert_settings_ack(&mut server_io).await;

    let lease = session.lease_stream().await.expect("lease");
    let first_body = b"first-data".to_vec();
    let second_body = b"second".to_vec();
    let first_submit = lease.submit_frame(data_frame(lease.stream_id(), first_body.clone(), false));
    let second_submit =
        lease.submit_frame(data_frame(lease.stream_id(), second_body.clone(), true));
    tokio::pin!(first_submit);
    tokio::pin!(second_submit);

    assert!(
        timeout(Duration::from_millis(100), &mut first_submit)
            .await
            .is_err(),
        "first DATA must be pending before the peer expands the stream window"
    );
    assert!(
        timeout(Duration::from_millis(100), &mut second_submit)
            .await
            .is_err(),
        "later same-stream DATA must remain pending behind the first DATA"
    );

    write_test_frame(&mut server_io, &window_update_frame(lease.stream_id(), 1))
        .await
        .expect("window update enough only for second DATA");
    assert!(
        timeout(Duration::from_millis(100), read_test_frame(&mut server_io))
            .await
            .is_err(),
        "later same-stream DATA must not bypass an earlier blocked DATA frame"
    );

    write_test_frame(&mut server_io, &window_update_frame(lease.stream_id(), 10))
        .await
        .expect("window update enough for both DATA frames in order");
    let first_upstream_data = read_test_frame(&mut server_io)
        .await
        .expect("first upstream data");
    assert_eq!(first_upstream_data.header.stream_id, lease.stream_id());
    assert_eq!(first_upstream_data.payload, FramePayload::Data(first_body));
    assert_eq!(first_upstream_data.header.flags & FLAG_END_STREAM, 0);
    first_submit.await.expect("first submit completes");

    let second_upstream_data = read_test_frame(&mut server_io)
        .await
        .expect("second upstream data");
    assert_eq!(second_upstream_data.header.stream_id, lease.stream_id());
    assert_eq!(
        second_upstream_data.payload,
        FramePayload::Data(second_body)
    );
    assert_eq!(
        second_upstream_data.header.flags & FLAG_END_STREAM,
        FLAG_END_STREAM
    );
    second_submit.await.expect("second submit completes");

    drop(session);
    drop(server_io);
    owner.await.expect("owner task");
}

#[tokio::test]
async fn pending_outbound_request_data_does_not_block_owner_read_loop() {
    let (client_io, mut server_io) = duplex(131_072);
    let (session, owner) = Http2SharedSession::spawn(
        client_io,
        Http2SharedSessionConfig::new(2, 8, 4).expect("config"),
    )
    .expect("spawn session");

    let lease = session.lease_stream().await.expect("lease");
    let body = vec![3; 65_536];
    let submit = lease.submit_frame(data_frame(lease.stream_id(), body, false));
    tokio::pin!(submit);

    assert!(
        timeout(Duration::from_millis(100), &mut submit)
            .await
            .is_err(),
        "submit must be pending before the peer expands windows"
    );

    let opaque = *b"blocked!";
    write_test_frame(&mut server_io, &ping_frame(opaque))
        .await
        .expect("ping while data blocked");
    let ping_ack = read_test_frame(&mut server_io)
        .await
        .expect("ping ack while data blocked");
    assert_eq!(ping_ack.header.frame_type, FrameType::Ping);
    assert_eq!(ping_ack.header.flags & FLAG_ACK, FLAG_ACK);
    assert!(matches!(
        ping_ack.payload,
        FramePayload::Ping {
            ack: true,
            opaque: returned
        } if returned == opaque
    ));

    write_test_frame(
        &mut server_io,
        &window_update_frame(StreamId::connection(), 1),
    )
    .await
    .expect("connection window update");
    write_test_frame(&mut server_io, &window_update_frame(lease.stream_id(), 1))
        .await
        .expect("stream window update");
    let upstream_data = read_test_frame(&mut server_io)
        .await
        .expect("released upstream data");
    assert_eq!(upstream_data.header.stream_id, lease.stream_id());
    submit.await.expect("submit completes after updates");

    drop(session);
    drop(server_io);
    owner.await.expect("owner task");
}

fn headers_frame(stream_id: StreamId, payload: &[u8], end_stream: bool) -> Frame {
    let flags = if end_stream {
        FLAG_END_STREAM | FLAG_END_HEADERS
    } else {
        FLAG_END_HEADERS
    };
    headers_frame_with_flags(stream_id, payload.to_vec(), flags)
}

fn response_headers_frame(stream_id: StreamId, value: &str, end_stream: bool) -> Frame {
    let mut encoder =
        fingerprint_proxy_hpack::Encoder::new(fingerprint_proxy_hpack::EncoderConfig {
            max_dynamic_table_size: 4096,
            use_huffman: false,
        });
    let block = encoder.encode_literal_without_indexing(&HpackHeaderField {
        name: b"x-test".to_vec(),
        value: value.as_bytes().to_vec(),
    });
    let flags = if end_stream {
        FLAG_END_STREAM | FLAG_END_HEADERS
    } else {
        FLAG_END_HEADERS
    };
    headers_frame_with_flags(stream_id, block, flags)
}

fn headers_frame_with_flags(stream_id: StreamId, payload: Vec<u8>, flags: u8) -> Frame {
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

fn data_frame(stream_id: StreamId, payload: Vec<u8>, end_stream: bool) -> Frame {
    Frame {
        header: FrameHeader {
            length: payload.len() as u32,
            frame_type: FrameType::Data,
            flags: if end_stream { FLAG_END_STREAM } else { 0 },
            stream_id,
        },
        payload: FramePayload::Data(payload),
    }
}

fn settings_frame() -> Frame {
    Frame {
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
    }
}

fn settings_max_concurrent_streams_frame(value: u32) -> Frame {
    let settings = Settings::new(vec![Setting { id: 0x3, value }]);
    Frame {
        header: FrameHeader {
            length: settings.encode().len() as u32,
            frame_type: FrameType::Settings,
            flags: 0,
            stream_id: StreamId::connection(),
        },
        payload: FramePayload::Settings {
            ack: false,
            settings,
        },
    }
}

fn settings_initial_window_size_frame(value: u32) -> Frame {
    let settings = Settings::new(vec![Setting { id: 0x4, value }]);
    Frame {
        header: FrameHeader {
            length: settings.encode().len() as u32,
            frame_type: FrameType::Settings,
            flags: 0,
            stream_id: StreamId::connection(),
        },
        payload: FramePayload::Settings {
            ack: false,
            settings,
        },
    }
}

async fn assert_settings_ack<I>(io: &mut I)
where
    I: AsyncRead + Unpin,
{
    let settings_ack = read_test_frame(io).await.expect("settings ack");
    assert_eq!(settings_ack.header.frame_type, FrameType::Settings);
    assert_eq!(settings_ack.header.flags & FLAG_ACK, FLAG_ACK);
    assert!(matches!(
        settings_ack.payload,
        FramePayload::Settings {
            ack: true,
            settings: _
        }
    ));
}

fn ping_frame(opaque: [u8; 8]) -> Frame {
    Frame {
        header: FrameHeader {
            length: 8,
            frame_type: FrameType::Ping,
            flags: 0,
            stream_id: StreamId::connection(),
        },
        payload: FramePayload::Ping { ack: false, opaque },
    }
}

fn goaway_frame(last_stream_id: StreamId, error_code: u32) -> Frame {
    Frame {
        header: FrameHeader {
            length: 8,
            frame_type: FrameType::GoAway,
            flags: 0,
            stream_id: StreamId::connection(),
        },
        payload: FramePayload::GoAway {
            last_stream_id,
            error_code,
            debug_data: Vec::new(),
        },
    }
}

fn goaway_rejected_stream_message(
    stream_id: StreamId,
    last_stream_id: StreamId,
    error_code: u32,
) -> String {
    format!(
        "HTTP/2 shared session GOAWAY rejected stream {} with last_stream_id={} error_code={}; retryable unavailable: session draining",
        stream_id.as_u32(),
        last_stream_id.as_u32(),
        error_code
    )
}

fn window_update_frame(stream_id: StreamId, increment: u32) -> Frame {
    Frame {
        header: FrameHeader {
            length: 4,
            frame_type: FrameType::WindowUpdate,
            flags: 0,
            stream_id,
        },
        payload: FramePayload::WindowUpdate {
            window_size_increment: increment,
        },
    }
}

fn assert_window_update(frame: &Frame, stream_id: StreamId, increment: u32) {
    assert_eq!(frame.header.frame_type, FrameType::WindowUpdate);
    assert_eq!(frame.header.stream_id, stream_id);
    assert_eq!(
        frame.payload,
        FramePayload::WindowUpdate {
            window_size_increment: increment,
        }
    );
}

fn assert_response_header_value(
    event: &Http2ResponseEvent,
    expected_name: &str,
    expected_value: &str,
    expected_end_stream: bool,
) {
    match event {
        Http2ResponseEvent::Headers { fields, end_stream } => {
            assert_eq!(*end_stream, expected_end_stream);
            assert!(fields
                .iter()
                .any(|field| field.name == expected_name && field.value == expected_value));
        }
        _ => panic!("unexpected response event"),
    }
}

async fn read_test_frame<I>(io: &mut I) -> io::Result<Frame>
where
    I: AsyncRead + Unpin,
{
    let mut header_bytes = [0u8; 9];
    io.read_exact(&mut header_bytes).await?;
    let header = parse_frame_header(&header_bytes).expect("parse frame header");
    let mut bytes = Vec::with_capacity(9 + header.length as usize);
    bytes.extend_from_slice(&header_bytes);
    bytes.resize(9 + header.length as usize, 0);
    io.read_exact(&mut bytes[9..]).await?;
    let (frame, consumed) = parse_frame(&bytes).expect("parse frame");
    assert_eq!(consumed, bytes.len());
    Ok(frame)
}

async fn write_test_frame<I>(io: &mut I, frame: &Frame) -> io::Result<()>
where
    I: AsyncWrite + Unpin,
{
    let bytes = serialize_frame(frame).expect("serialize frame");
    io.write_all(&bytes).await
}
