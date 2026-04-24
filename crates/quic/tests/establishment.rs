use fingerprint_proxy_quic::{
    parse_packet_header, QuicEstablishment, QuicEstablishmentError, QuicPacketHeader, QuicState,
};

fn client_initial_packet() -> Vec<u8> {
    vec![
        0xc0, 0x00, 0x00, 0x00, 0x01, 0x04, 0xaa, 0xbb, 0xcc, 0xdd, 0x04, 0x11, 0x22, 0x33, 0x44,
        0x00, 0x02, 0x01,
    ]
}

#[test]
fn accepts_valid_client_initial_and_confirms_handshake() {
    let header = parse_packet_header(&client_initial_packet(), 0).expect("parse");
    let mut establishment = QuicEstablishment::new();

    let initial = establishment
        .accept_client_initial(&header, QuicEstablishment::MIN_CLIENT_INITIAL_DATAGRAM_LEN)
        .expect("accept");

    assert_eq!(initial.version, 1);
    assert_eq!(initial.destination_connection_id, [0xaa, 0xbb, 0xcc, 0xdd]);
    assert_eq!(initial.source_connection_id, [0x11, 0x22, 0x33, 0x44]);
    assert_eq!(establishment.state(), QuicState::HandshakeInProgress);

    assert_eq!(
        establishment.confirm_handshake().expect("confirm"),
        QuicState::Established
    );
}

#[test]
fn rejects_non_initial_and_too_small_initial_datagram() {
    let short = QuicPacketHeader::Short(fingerprint_proxy_quic::ShortPacketHeader {
        destination_connection_id: vec![1, 2, 3, 4],
        key_phase: false,
        packet_number_length: 1,
        header_length: 6,
    });
    let mut establishment = QuicEstablishment::new();
    let err = establishment
        .accept_client_initial(&short, QuicEstablishment::MIN_CLIENT_INITIAL_DATAGRAM_LEN)
        .expect_err("short must fail");
    assert_eq!(err, QuicEstablishmentError::ExpectedInitialLongPacket);

    let header = parse_packet_header(&client_initial_packet(), 0).expect("parse");
    let err = establishment
        .accept_client_initial(
            &header,
            QuicEstablishment::MIN_CLIENT_INITIAL_DATAGRAM_LEN - 1,
        )
        .expect_err("too small");
    assert_eq!(
        err,
        QuicEstablishmentError::InitialDatagramTooSmall {
            actual: QuicEstablishment::MIN_CLIENT_INITIAL_DATAGRAM_LEN - 1,
            minimum: QuicEstablishment::MIN_CLIENT_INITIAL_DATAGRAM_LEN
        }
    );
}
