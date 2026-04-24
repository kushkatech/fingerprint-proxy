use fingerprint_proxy_quic::{
    parse_long_header, parse_packet_header, parse_short_header, LongPacketType, QuicPacketError,
    QuicPacketHeader,
};

fn client_initial_header() -> Vec<u8> {
    vec![
        0xc0, // long header, fixed bit, Initial, packet number length = 1
        0x00, 0x00, 0x00, 0x01, // version
        0x04, // dcid len
        0xaa, 0xbb, 0xcc, 0xdd, // dcid
        0x04, // scid len
        0x11, 0x22, 0x33, 0x44, // scid
        0x00, // token length
        0x02, // packet length
        0x01, // packet number
    ]
}

#[test]
fn parses_initial_long_packet_header_deterministically() {
    let header = parse_long_header(&client_initial_header()).expect("parse initial");

    assert_eq!(header.packet_type, LongPacketType::Initial);
    assert_eq!(header.version, 1);
    assert_eq!(header.destination_connection_id, [0xaa, 0xbb, 0xcc, 0xdd]);
    assert_eq!(header.source_connection_id, [0x11, 0x22, 0x33, 0x44]);
    assert_eq!(header.token, Vec::<u8>::new());
    assert_eq!(header.length, Some(2));
    assert_eq!(header.packet_number_length, 1);
    assert_eq!(header.header_length, client_initial_header().len());
}

#[test]
fn packet_header_dispatches_long_and_short_forms() {
    let long = parse_packet_header(&client_initial_header(), 4).expect("long");
    assert!(matches!(long, QuicPacketHeader::Long(_)));

    let short = parse_packet_header(&[0x43, 0xaa, 0xbb, 0x01, 0x02, 0x03, 0xff], 2).expect("short");
    assert!(matches!(short, QuicPacketHeader::Short(_)));
}

#[test]
fn parses_short_header_with_configured_connection_id_len() {
    let header = parse_short_header(&[0x47, 0xaa, 0xbb, 0x01, 0x02, 0x03, 0xff], 2).expect("short");

    assert_eq!(header.destination_connection_id, [0xaa, 0xbb]);
    assert!(header.key_phase);
    assert_eq!(header.packet_number_length, 4);
    assert_eq!(header.header_length, 7);
}

#[test]
fn rejects_missing_fixed_bit_and_truncated_connection_ids() {
    let err = parse_packet_header(&[0x80], 0).expect_err("missing fixed bit");
    assert_eq!(err, QuicPacketError::MissingFixedBit);

    let err = parse_long_header(&[0xc0, 0, 0, 0, 1, 4, 1]).expect_err("truncated dcid");
    assert_eq!(err, QuicPacketError::Truncated("destination connection id"));
}

#[test]
fn rejects_connection_ids_longer_than_quic_limit() {
    let mut input = vec![0xc0, 0, 0, 0, 1, 21];
    input.extend([0u8; 21]);
    let err = parse_long_header(&input).expect_err("long dcid");
    assert_eq!(err, QuicPacketError::ConnectionIdTooLong);
}
