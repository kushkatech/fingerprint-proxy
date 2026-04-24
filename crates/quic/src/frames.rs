use crate::varint::{decode_varint, QuicVarintError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuicFrameError {
    Empty,
    Truncated(&'static str),
    InvalidVarint(&'static str),
    UnknownFrameType(u64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuicFrame {
    Padding,
    Ping,
    Ack {
        largest_acknowledged: u64,
        ack_delay: u64,
        ack_range_count: u64,
        first_ack_range: u64,
        ecn_counts: Option<EcnCounts>,
    },
    Crypto {
        offset: u64,
        data: Vec<u8>,
    },
    Stream {
        stream_id: u64,
        offset: u64,
        data: Vec<u8>,
        fin: bool,
    },
    ConnectionClose {
        error_code: u64,
        frame_type: u64,
        reason_phrase: Vec<u8>,
    },
    ApplicationClose {
        error_code: u64,
        reason_phrase: Vec<u8>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EcnCounts {
    pub ect0: u64,
    pub ect1: u64,
    pub ce: u64,
}

pub fn parse_frame(input: &[u8]) -> Result<(QuicFrame, usize), QuicFrameError> {
    let (frame_type, used_type) = decode_context(input, "frame type")?;
    let mut idx = used_type;

    match frame_type {
        0x00 => Ok((QuicFrame::Padding, idx)),
        0x01 => Ok((QuicFrame::Ping, idx)),
        0x02 | 0x03 => {
            let largest_acknowledged = read_varint(input, &mut idx, "largest acknowledged")?;
            let ack_delay = read_varint(input, &mut idx, "ack delay")?;
            let ack_range_count = read_varint(input, &mut idx, "ack range count")?;
            let first_ack_range = read_varint(input, &mut idx, "first ack range")?;
            let ecn_counts = if frame_type == 0x03 {
                Some(EcnCounts {
                    ect0: read_varint(input, &mut idx, "ecn ect0")?,
                    ect1: read_varint(input, &mut idx, "ecn ect1")?,
                    ce: read_varint(input, &mut idx, "ecn ce")?,
                })
            } else {
                None
            };
            Ok((
                QuicFrame::Ack {
                    largest_acknowledged,
                    ack_delay,
                    ack_range_count,
                    first_ack_range,
                    ecn_counts,
                },
                idx,
            ))
        }
        0x06 => {
            let offset = read_varint(input, &mut idx, "crypto offset")?;
            let len = read_varint(input, &mut idx, "crypto length")?;
            let data = read_bytes(input, &mut idx, len, "crypto data")?;
            Ok((QuicFrame::Crypto { offset, data }, idx))
        }
        0x08..=0x0f => {
            let has_offset = frame_type & 0x04 != 0;
            let has_length = frame_type & 0x02 != 0;
            let fin = frame_type & 0x01 != 0;
            let stream_id = read_varint(input, &mut idx, "stream id")?;
            let offset = if has_offset {
                read_varint(input, &mut idx, "stream offset")?
            } else {
                0
            };
            let data = if has_length {
                let len = read_varint(input, &mut idx, "stream length")?;
                read_bytes(input, &mut idx, len, "stream data")?
            } else {
                let data = input[idx..].to_vec();
                idx = input.len();
                data
            };
            Ok((
                QuicFrame::Stream {
                    stream_id,
                    offset,
                    data,
                    fin,
                },
                idx,
            ))
        }
        0x1c => {
            let error_code = read_varint(input, &mut idx, "connection close error code")?;
            let frame_type = read_varint(input, &mut idx, "connection close frame type")?;
            let reason_len = read_varint(input, &mut idx, "connection close reason length")?;
            let reason_phrase = read_bytes(input, &mut idx, reason_len, "connection close reason")?;
            Ok((
                QuicFrame::ConnectionClose {
                    error_code,
                    frame_type,
                    reason_phrase,
                },
                idx,
            ))
        }
        0x1d => {
            let error_code = read_varint(input, &mut idx, "application close error code")?;
            let reason_len = read_varint(input, &mut idx, "application close reason length")?;
            let reason_phrase =
                read_bytes(input, &mut idx, reason_len, "application close reason")?;
            Ok((
                QuicFrame::ApplicationClose {
                    error_code,
                    reason_phrase,
                },
                idx,
            ))
        }
        other => Err(QuicFrameError::UnknownFrameType(other)),
    }
}

pub fn parse_frames(mut input: &[u8]) -> Result<Vec<QuicFrame>, QuicFrameError> {
    let mut frames = Vec::new();
    while !input.is_empty() {
        let (frame, used) = parse_frame(input)?;
        if used == 0 {
            return Err(QuicFrameError::Truncated("frame"));
        }
        frames.push(frame);
        input = &input[used..];
    }
    Ok(frames)
}

fn read_varint(
    input: &[u8],
    idx: &mut usize,
    context: &'static str,
) -> Result<u64, QuicFrameError> {
    let (value, used) = decode_context(&input[*idx..], context)?;
    *idx += used;
    Ok(value)
}

fn read_bytes(
    input: &[u8],
    idx: &mut usize,
    len: u64,
    context: &'static str,
) -> Result<Vec<u8>, QuicFrameError> {
    let len: usize = len
        .try_into()
        .map_err(|_| QuicFrameError::InvalidVarint(context))?;
    if input.len() < *idx + len {
        return Err(QuicFrameError::Truncated(context));
    }
    let out = input[*idx..*idx + len].to_vec();
    *idx += len;
    Ok(out)
}

fn decode_context(input: &[u8], context: &'static str) -> Result<(u64, usize), QuicFrameError> {
    decode_varint(input).map_err(|err| match err {
        QuicVarintError::UnexpectedEof => QuicFrameError::Truncated(context),
        QuicVarintError::ValueOutOfRange => QuicFrameError::InvalidVarint(context),
    })
}
