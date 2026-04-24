use crate::varint::{decode_varint, QuicVarintError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuicPacketError {
    Empty,
    MissingFixedBit,
    Truncated(&'static str),
    InvalidVarint(&'static str),
    ConnectionIdTooLong,
    ShortHeaderDestinationIdTooLong,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LongPacketType {
    Initial,
    ZeroRtt,
    Handshake,
    Retry,
}

impl LongPacketType {
    fn from_first_byte(first: u8) -> Self {
        match (first & 0x30) >> 4 {
            0 => Self::Initial,
            1 => Self::ZeroRtt,
            2 => Self::Handshake,
            3 => Self::Retry,
            _ => unreachable!(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LongPacketHeader {
    pub packet_type: LongPacketType,
    pub version: u32,
    pub destination_connection_id: Vec<u8>,
    pub source_connection_id: Vec<u8>,
    pub token: Vec<u8>,
    pub length: Option<u64>,
    pub packet_number_length: usize,
    pub header_length: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShortPacketHeader {
    pub destination_connection_id: Vec<u8>,
    pub key_phase: bool,
    pub packet_number_length: usize,
    pub header_length: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuicPacketHeader {
    Long(LongPacketHeader),
    Short(ShortPacketHeader),
}

pub fn parse_packet_header(
    input: &[u8],
    short_destination_connection_id_len: usize,
) -> Result<QuicPacketHeader, QuicPacketError> {
    let Some(&first) = input.first() else {
        return Err(QuicPacketError::Empty);
    };

    if first & 0x40 == 0 {
        return Err(QuicPacketError::MissingFixedBit);
    }

    if first & 0x80 != 0 {
        parse_long_header(input).map(QuicPacketHeader::Long)
    } else {
        parse_short_header(input, short_destination_connection_id_len).map(QuicPacketHeader::Short)
    }
}

pub fn parse_long_header(input: &[u8]) -> Result<LongPacketHeader, QuicPacketError> {
    if input.len() < 7 {
        return Err(QuicPacketError::Truncated("long header prefix"));
    }

    let first = input[0];
    if first & 0x80 == 0 {
        return Err(QuicPacketError::Truncated("long header form"));
    }
    if first & 0x40 == 0 {
        return Err(QuicPacketError::MissingFixedBit);
    }

    let packet_type = LongPacketType::from_first_byte(first);
    let version = u32::from_be_bytes([input[1], input[2], input[3], input[4]]);

    let mut idx = 5usize;
    let dcid_len = input[idx] as usize;
    idx += 1;
    if dcid_len > 20 {
        return Err(QuicPacketError::ConnectionIdTooLong);
    }
    if input.len() < idx + dcid_len + 1 {
        return Err(QuicPacketError::Truncated("destination connection id"));
    }
    let destination_connection_id = input[idx..idx + dcid_len].to_vec();
    idx += dcid_len;

    let scid_len = input[idx] as usize;
    idx += 1;
    if scid_len > 20 {
        return Err(QuicPacketError::ConnectionIdTooLong);
    }
    if input.len() < idx + scid_len {
        return Err(QuicPacketError::Truncated("source connection id"));
    }
    let source_connection_id = input[idx..idx + scid_len].to_vec();
    idx += scid_len;

    let mut token = Vec::new();
    if packet_type == LongPacketType::Initial {
        let (token_len, used) = decode_context(&input[idx..], "initial token length")?;
        idx += used;
        let token_len: usize = token_len
            .try_into()
            .map_err(|_| QuicPacketError::InvalidVarint("initial token length"))?;
        if input.len() < idx + token_len {
            return Err(QuicPacketError::Truncated("initial token"));
        }
        token = input[idx..idx + token_len].to_vec();
        idx += token_len;
    }

    let mut length = None;
    if packet_type != LongPacketType::Retry {
        let (packet_len, used) = decode_context(&input[idx..], "packet length")?;
        idx += used;
        length = Some(packet_len);
    }

    let packet_number_length = ((first & 0x03) as usize) + 1;
    if packet_type != LongPacketType::Retry && input.len() < idx + packet_number_length {
        return Err(QuicPacketError::Truncated("packet number"));
    }

    Ok(LongPacketHeader {
        packet_type,
        version,
        destination_connection_id,
        source_connection_id,
        token,
        length,
        packet_number_length,
        header_length: idx + packet_number_length,
    })
}

pub fn parse_short_header(
    input: &[u8],
    destination_connection_id_len: usize,
) -> Result<ShortPacketHeader, QuicPacketError> {
    let Some(&first) = input.first() else {
        return Err(QuicPacketError::Empty);
    };
    if first & 0x80 != 0 {
        return Err(QuicPacketError::Truncated("short header form"));
    }
    if first & 0x40 == 0 {
        return Err(QuicPacketError::MissingFixedBit);
    }
    if destination_connection_id_len > 20 {
        return Err(QuicPacketError::ShortHeaderDestinationIdTooLong);
    }

    let packet_number_length = ((first & 0x03) as usize) + 1;
    let header_length = 1 + destination_connection_id_len + packet_number_length;
    if input.len() < header_length {
        return Err(QuicPacketError::Truncated("short header"));
    }

    Ok(ShortPacketHeader {
        destination_connection_id: input[1..1 + destination_connection_id_len].to_vec(),
        key_phase: first & 0x04 != 0,
        packet_number_length,
        header_length,
    })
}

fn decode_context(input: &[u8], context: &'static str) -> Result<(u64, usize), QuicPacketError> {
    decode_varint(input).map_err(|err| match err {
        QuicVarintError::UnexpectedEof => QuicPacketError::Truncated(context),
        QuicVarintError::ValueOutOfRange => QuicPacketError::InvalidVarint(context),
    })
}
