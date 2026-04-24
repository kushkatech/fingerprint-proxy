use fingerprint_proxy_quic::{
    CloseReason, ConnectionError, ConnectionOperation, ConnectionState, QuicConnection,
    QuicConnectionId,
};

#[test]
fn lifecycle_transitions_are_deterministic() {
    let mut connection = QuicConnection::new(QuicConnectionId::new(42));
    assert_eq!(connection.id(), QuicConnectionId::new(42));
    assert_eq!(connection.state(), ConnectionState::Initial);

    connection.start_handshake().expect("handshake start");
    assert_eq!(connection.state(), ConnectionState::Handshake);

    connection.mark_established().expect("established");
    assert_eq!(connection.state(), ConnectionState::Established);

    connection
        .record_incoming_packet()
        .expect("incoming packet");
    connection
        .record_outgoing_packet()
        .expect("outgoing packet");
    assert_eq!(connection.packets_received(), 1);
    assert_eq!(connection.packets_sent(), 1);

    connection.start_draining().expect("draining");
    assert_eq!(connection.state(), ConnectionState::Draining);

    connection
        .close(CloseReason::Application)
        .expect("close succeeds");
    assert_eq!(connection.state(), ConnectionState::Closed);
    assert_eq!(connection.close_reason(), Some(CloseReason::Application));
}

#[test]
fn invalid_state_transition_returns_context() {
    let mut connection = QuicConnection::new(QuicConnectionId::new(7));

    let err = connection.mark_established().expect_err("must fail");
    assert_eq!(
        err,
        ConnectionError {
            from: ConnectionState::Initial,
            operation: ConnectionOperation::MarkEstablished
        }
    );

    connection.start_handshake().expect("handshake start");
    connection.mark_established().expect("established");

    let err = connection.start_handshake().expect_err("must fail");
    assert_eq!(
        err,
        ConnectionError {
            from: ConnectionState::Established,
            operation: ConnectionOperation::StartHandshake
        }
    );
}

#[test]
fn packet_accounting_requires_established_or_draining_state() {
    let mut connection = QuicConnection::new(QuicConnectionId::new(11));

    let err = connection
        .record_incoming_packet()
        .expect_err("initial state must fail");
    assert_eq!(
        err,
        ConnectionError {
            from: ConnectionState::Initial,
            operation: ConnectionOperation::RecordIncomingPacket
        }
    );

    connection.start_handshake().expect("handshake start");
    let err = connection
        .record_outgoing_packet()
        .expect_err("handshake state must fail");
    assert_eq!(
        err,
        ConnectionError {
            from: ConnectionState::Handshake,
            operation: ConnectionOperation::RecordOutgoingPacket
        }
    );
}

#[test]
fn closed_connection_rejects_operations() {
    let mut connection = QuicConnection::new(QuicConnectionId::new(100));
    connection
        .close(CloseReason::TransportError)
        .expect("first close succeeds");

    let err = connection
        .close(CloseReason::IdleTimeout)
        .expect_err("must fail");
    assert_eq!(
        err,
        ConnectionError {
            from: ConnectionState::Closed,
            operation: ConnectionOperation::Close
        }
    );

    let err = connection
        .record_incoming_packet()
        .expect_err("closed state must fail");
    assert_eq!(
        err,
        ConnectionError {
            from: ConnectionState::Closed,
            operation: ConnectionOperation::RecordIncomingPacket
        }
    );
}
