use crate::varint::{decode_varint, encode_varint, map_varint_error, VarintError};
use fingerprint_proxy_core::error::FpError;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    Data,
    Headers,
    Settings,
    Unknown(u64),
}

impl FrameType {
    pub fn as_u64(self) -> u64 {
        match self {
            FrameType::Data => 0x0,
            FrameType::Headers => 0x1,
            FrameType::Settings => 0x4,
            FrameType::Unknown(v) => v,
        }
    }

    pub fn from_u64(v: u64) -> Self {
        match v {
            0x0 => FrameType::Data,
            0x1 => FrameType::Headers,
            0x4 => FrameType::Settings,
            other => FrameType::Unknown(other),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FramePayload {
    Opaque(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub frame_type: FrameType,
    pub payload: FramePayload,
}

impl Frame {
    pub fn new(frame_type: FrameType, payload: Vec<u8>) -> Self {
        Self {
            frame_type,
            payload: FramePayload::Opaque(payload),
        }
    }

    pub fn payload_bytes(&self) -> &[u8] {
        match &self.payload {
            FramePayload::Opaque(b) => b.as_slice(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Http3FrameError {
    Truncated,
    InvalidVarint,
    InvalidLength,
}

impl fmt::Display for Http3FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Http3FrameError::Truncated => f.write_str("truncated frame"),
            Http3FrameError::InvalidVarint => f.write_str("invalid varint"),
            Http3FrameError::InvalidLength => f.write_str("invalid length"),
        }
    }
}

impl std::error::Error for Http3FrameError {}

pub fn parse_frame(input: &[u8]) -> Result<(Frame, usize), FpError> {
    let (raw_type, used_t) =
        decode_varint(input).map_err(|e| map_varint_error("HTTP/3 frame type", e))?;
    let (len, used_l) =
        decode_varint(&input[used_t..]).map_err(|e| map_varint_error("HTTP/3 frame length", e))?;

    let header_len = used_t + used_l;
    let payload_len: usize = len
        .try_into()
        .map_err(|_| FpError::invalid_protocol_data("HTTP/3 frame length too large"))?;

    if input.len() < header_len + payload_len {
        return Err(FpError::invalid_protocol_data(
            "HTTP/3 truncated frame payload",
        ));
    }

    let payload = input[header_len..header_len + payload_len].to_vec();
    let frame = Frame::new(FrameType::from_u64(raw_type), payload);
    Ok((frame, header_len + payload_len))
}

pub fn parse_frames(input: &[u8]) -> Result<Vec<Frame>, FpError> {
    let mut out = Vec::new();
    let mut idx = 0usize;
    while idx < input.len() {
        let (frame, used) = parse_frame(&input[idx..])?;
        idx += used;
        out.push(frame);
    }
    Ok(out)
}

pub fn serialize_frame(frame: &Frame) -> Result<Vec<u8>, FpError> {
    let t = encode_varint(frame.frame_type.as_u64())
        .map_err(|e| map_varint_error("HTTP/3 frame type", e))?;
    let len = encode_varint(frame.payload_bytes().len() as u64)
        .map_err(|e| map_varint_error("HTTP/3 frame length", e))?;

    let mut out = Vec::with_capacity(t.len() + len.len() + frame.payload_bytes().len());
    out.extend_from_slice(&t);
    out.extend_from_slice(&len);
    out.extend_from_slice(frame.payload_bytes());
    Ok(out)
}

pub fn map_frame_error(err: Http3FrameError) -> FpError {
    match err {
        Http3FrameError::Truncated => FpError::invalid_protocol_data("HTTP/3 truncated frame"),
        Http3FrameError::InvalidVarint => FpError::invalid_protocol_data("HTTP/3 invalid varint"),
        Http3FrameError::InvalidLength => FpError::invalid_protocol_data("HTTP/3 invalid length"),
    }
}

pub fn map_varint_error_to_frame_error(err: VarintError) -> Http3FrameError {
    match err {
        VarintError::UnexpectedEof => Http3FrameError::Truncated,
        VarintError::ValueOutOfRange => Http3FrameError::InvalidVarint,
    }
}
