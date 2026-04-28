use crate::data::{parse_data_payload, serialize_data_payload};
use crate::settings::Settings;
use crate::streams::StreamId;
use std::fmt;

pub const FLAG_PUSH_PROMISE_PADDED: u8 = 0x8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    Data,
    Headers,
    Priority,
    RstStream,
    Settings,
    PushPromise,
    Ping,
    GoAway,
    WindowUpdate,
    Continuation,
}

impl FrameType {
    pub fn as_u8(self) -> u8 {
        match self {
            FrameType::Data => 0x0,
            FrameType::Headers => 0x1,
            FrameType::Priority => 0x2,
            FrameType::RstStream => 0x3,
            FrameType::Settings => 0x4,
            FrameType::PushPromise => 0x5,
            FrameType::Ping => 0x6,
            FrameType::GoAway => 0x7,
            FrameType::WindowUpdate => 0x8,
            FrameType::Continuation => 0x9,
        }
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0x0 => FrameType::Data,
            0x1 => FrameType::Headers,
            0x2 => FrameType::Priority,
            0x3 => FrameType::RstStream,
            0x4 => FrameType::Settings,
            0x5 => FrameType::PushPromise,
            0x6 => FrameType::Ping,
            0x7 => FrameType::GoAway,
            0x8 => FrameType::WindowUpdate,
            0x9 => FrameType::Continuation,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameHeader {
    pub length: u32,
    pub frame_type: FrameType,
    pub flags: u8,
    pub stream_id: StreamId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FramePayload {
    Data(Vec<u8>),
    Headers(Vec<u8>),
    Priority(Vec<u8>),
    RstStream {
        error_code: u32,
    },
    Settings {
        ack: bool,
        settings: Settings,
    },
    PushPromise(Vec<u8>),
    Ping {
        ack: bool,
        opaque: [u8; 8],
    },
    GoAway {
        last_stream_id: StreamId,
        error_code: u32,
        debug_data: Vec<u8>,
    },
    WindowUpdate {
        window_size_increment: u32,
    },
    Continuation(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub header: FrameHeader,
    pub payload: FramePayload,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Http2FrameError {
    UnexpectedEof,
    InvalidFrameType(u8),
    InvalidLength {
        expected: usize,
        actual: usize,
    },
    ReservedBitSetInStreamId,
    InvalidStreamIdForFrameType {
        frame_type: FrameType,
        stream_id: u32,
    },
    InvalidSettingsPayloadLength,
    InvalidSettingsAckPayload,
    AckFlagMismatch {
        frame_type: FrameType,
    },
    InvalidPingPayloadLength {
        actual: usize,
    },
    InvalidGoAwayPayloadLength {
        actual: usize,
    },
    ReservedBitSetInGoAwayLastStreamId,
    InvalidRstStreamPayloadLength {
        actual: usize,
    },
    InvalidWindowUpdatePayloadLength {
        actual: usize,
    },
    ReservedBitSetInWindowUpdate,
    InvalidPushPromisePayloadLength {
        actual: usize,
    },
    ReservedBitSetInPushPromisePromisedStreamId,
    InvalidPushPromisePromisedStreamId,
    InvalidDataPadding {
        pad_length: u8,
        payload_length: usize,
    },
    UnsupportedDataPaddingOnSerialize,
    LengthOutOfRange(u32),
}

impl fmt::Display for Http2FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Http2FrameError::UnexpectedEof => f.write_str("unexpected EOF"),
            Http2FrameError::InvalidFrameType(t) => write!(f, "invalid frame type: {t}"),
            Http2FrameError::InvalidLength { expected, actual } => {
                write!(f, "invalid length: expected {expected}, got {actual}")
            }
            Http2FrameError::ReservedBitSetInStreamId => {
                f.write_str("reserved bit set in stream id")
            }
            Http2FrameError::InvalidStreamIdForFrameType {
                frame_type,
                stream_id,
            } => write!(
                f,
                "invalid stream id {stream_id} for frame type {:?}",
                frame_type
            ),
            Http2FrameError::InvalidSettingsPayloadLength => {
                f.write_str("invalid SETTINGS payload length")
            }
            Http2FrameError::InvalidSettingsAckPayload => {
                f.write_str("SETTINGS with ACK must have empty payload")
            }
            Http2FrameError::AckFlagMismatch { frame_type } => {
                write!(f, "ACK flag mismatch for frame type {:?}", frame_type)
            }
            Http2FrameError::InvalidPingPayloadLength { actual } => {
                write!(f, "PING payload length must be 8, got {actual}")
            }
            Http2FrameError::InvalidGoAwayPayloadLength { actual } => {
                write!(f, "GOAWAY payload length must be >= 8, got {actual}")
            }
            Http2FrameError::ReservedBitSetInGoAwayLastStreamId => {
                f.write_str("reserved bit set in GOAWAY last_stream_id")
            }
            Http2FrameError::InvalidRstStreamPayloadLength { actual } => {
                write!(f, "RST_STREAM payload length must be 4, got {actual}")
            }
            Http2FrameError::InvalidWindowUpdatePayloadLength { actual } => {
                write!(f, "WINDOW_UPDATE payload length must be 4, got {actual}")
            }
            Http2FrameError::ReservedBitSetInWindowUpdate => {
                f.write_str("reserved bit set in WINDOW_UPDATE increment")
            }
            Http2FrameError::InvalidPushPromisePayloadLength { actual } => write!(
                f,
                "PUSH_PROMISE payload length must include promised stream id, got {actual}"
            ),
            Http2FrameError::ReservedBitSetInPushPromisePromisedStreamId => {
                f.write_str("reserved bit set in PUSH_PROMISE promised stream id")
            }
            Http2FrameError::InvalidPushPromisePromisedStreamId => {
                f.write_str("PUSH_PROMISE promised stream id must be non-zero")
            }
            Http2FrameError::InvalidDataPadding {
                pad_length,
                payload_length,
            } => write!(
                f,
                "invalid DATA padding: pad_length {pad_length} is invalid for payload length {payload_length}"
            ),
            Http2FrameError::UnsupportedDataPaddingOnSerialize => {
                f.write_str("DATA padding is not supported for serialization")
            }
            Http2FrameError::LengthOutOfRange(v) => {
                write!(f, "frame length out of range (24-bit): {v}")
            }
        }
    }
}

impl std::error::Error for Http2FrameError {}

pub fn parse_frame_header(input: &[u8]) -> Result<FrameHeader, Http2FrameError> {
    if input.len() < 9 {
        return Err(Http2FrameError::UnexpectedEof);
    }
    let length = ((input[0] as u32) << 16) | ((input[1] as u32) << 8) | (input[2] as u32);
    let frame_type_raw = input[3];
    let flags = input[4];
    let stream_id_raw = u32::from_be_bytes([input[5], input[6], input[7], input[8]]);
    if (stream_id_raw & 0x8000_0000) != 0 {
        return Err(Http2FrameError::ReservedBitSetInStreamId);
    }
    let stream_id = StreamId(stream_id_raw);
    let frame_type = FrameType::from_u8(frame_type_raw)
        .ok_or(Http2FrameError::InvalidFrameType(frame_type_raw))?;
    Ok(FrameHeader {
        length,
        frame_type,
        flags,
        stream_id,
    })
}

pub fn serialize_frame_header(header: &FrameHeader) -> Result<[u8; 9], Http2FrameError> {
    if header.length > 0x00FF_FFFF {
        return Err(Http2FrameError::LengthOutOfRange(header.length));
    }
    if (header.stream_id.as_u32() & 0x8000_0000) != 0 {
        return Err(Http2FrameError::ReservedBitSetInStreamId);
    }
    let len = header.length;
    let mut out = [0u8; 9];
    out[0] = ((len >> 16) & 0xFF) as u8;
    out[1] = ((len >> 8) & 0xFF) as u8;
    out[2] = (len & 0xFF) as u8;
    out[3] = header.frame_type.as_u8();
    out[4] = header.flags;
    out[5..9].copy_from_slice(&header.stream_id.as_u32().to_be_bytes());
    Ok(out)
}

pub fn parse_frame(input: &[u8]) -> Result<(Frame, usize), Http2FrameError> {
    let header = parse_frame_header(input)?;
    let payload_len = header.length as usize;
    if input.len() < 9 + payload_len {
        return Err(Http2FrameError::UnexpectedEof);
    }
    let payload_bytes = &input[9..9 + payload_len];

    validate_stream_id_rules(&header)?;

    let payload = match header.frame_type {
        FrameType::Settings => parse_settings_frame(&header, payload_bytes)?,
        FrameType::Ping => parse_ping_frame(&header, payload_bytes)?,
        FrameType::GoAway => parse_goaway_frame(&header, payload_bytes)?,
        FrameType::WindowUpdate => parse_window_update_frame(&header, payload_bytes)?,
        FrameType::RstStream => parse_rst_stream_frame(&header, payload_bytes)?,
        FrameType::Data => FramePayload::Data(parse_data_payload(header.flags, payload_bytes)?),
        FrameType::Headers => FramePayload::Headers(payload_bytes.to_vec()),
        FrameType::Priority => FramePayload::Priority(payload_bytes.to_vec()),
        FrameType::PushPromise => FramePayload::PushPromise(payload_bytes.to_vec()),
        FrameType::Continuation => FramePayload::Continuation(payload_bytes.to_vec()),
    };

    Ok((Frame { header, payload }, 9 + payload_len))
}

pub fn serialize_frame(frame: &Frame) -> Result<Vec<u8>, Http2FrameError> {
    validate_flags_payload_consistency(frame)?;
    let payload_bytes = serialize_payload(frame.header.flags, &frame.payload)?;
    if frame.header.length as usize != payload_bytes.len() {
        return Err(Http2FrameError::InvalidLength {
            expected: frame.header.length as usize,
            actual: payload_bytes.len(),
        });
    }
    validate_stream_id_rules(&frame.header)?;

    let mut out = Vec::with_capacity(9 + payload_bytes.len());
    out.extend_from_slice(&serialize_frame_header(&frame.header)?);
    out.extend_from_slice(&payload_bytes);
    Ok(out)
}

pub fn parse_push_promise_promised_stream_id(
    flags: u8,
    payload: &[u8],
) -> Result<StreamId, Http2FrameError> {
    let promised_id_offset = if (flags & FLAG_PUSH_PROMISE_PADDED) != 0 {
        if payload.len() < 5 {
            return Err(Http2FrameError::InvalidPushPromisePayloadLength {
                actual: payload.len(),
            });
        }
        1
    } else {
        if payload.len() < 4 {
            return Err(Http2FrameError::InvalidPushPromisePayloadLength {
                actual: payload.len(),
            });
        }
        0
    };
    let raw = u32::from_be_bytes([
        payload[promised_id_offset],
        payload[promised_id_offset + 1],
        payload[promised_id_offset + 2],
        payload[promised_id_offset + 3],
    ]);
    if (raw & 0x8000_0000) != 0 {
        return Err(Http2FrameError::ReservedBitSetInPushPromisePromisedStreamId);
    }
    let promised_stream_id = StreamId(raw);
    if promised_stream_id.is_connection() {
        return Err(Http2FrameError::InvalidPushPromisePromisedStreamId);
    }
    Ok(promised_stream_id)
}

fn validate_flags_payload_consistency(frame: &Frame) -> Result<(), Http2FrameError> {
    match &frame.payload {
        FramePayload::Settings { ack, settings } => {
            let flag_ack = (frame.header.flags & 0x1) != 0;
            if flag_ack != *ack {
                return Err(Http2FrameError::AckFlagMismatch {
                    frame_type: FrameType::Settings,
                });
            }
            if *ack && !settings.entries.is_empty() {
                return Err(Http2FrameError::InvalidSettingsAckPayload);
            }
        }
        FramePayload::Ping { ack, opaque: _ } => {
            let flag_ack = (frame.header.flags & 0x1) != 0;
            if flag_ack != *ack {
                return Err(Http2FrameError::AckFlagMismatch {
                    frame_type: FrameType::Ping,
                });
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_stream_id_rules(header: &FrameHeader) -> Result<(), Http2FrameError> {
    let sid = header.stream_id.as_u32();
    match header.frame_type {
        FrameType::Settings | FrameType::Ping | FrameType::GoAway => {
            if sid != 0 {
                return Err(Http2FrameError::InvalidStreamIdForFrameType {
                    frame_type: header.frame_type,
                    stream_id: sid,
                });
            }
        }
        FrameType::WindowUpdate => {
            // stream id may be 0 (connection-level) or non-zero (stream-level)
        }
        FrameType::Data
        | FrameType::Headers
        | FrameType::Priority
        | FrameType::RstStream
        | FrameType::PushPromise
        | FrameType::Continuation => {
            if sid == 0 {
                return Err(Http2FrameError::InvalidStreamIdForFrameType {
                    frame_type: header.frame_type,
                    stream_id: sid,
                });
            }
        }
    }
    Ok(())
}

fn parse_settings_frame(
    header: &FrameHeader,
    payload: &[u8],
) -> Result<FramePayload, Http2FrameError> {
    let ack = (header.flags & 0x1) != 0;
    if ack {
        if !payload.is_empty() {
            return Err(Http2FrameError::InvalidSettingsAckPayload);
        }
        return Ok(FramePayload::Settings {
            ack,
            settings: Settings::new(Vec::new()),
        });
    }
    let settings =
        Settings::decode(payload).ok_or(Http2FrameError::InvalidSettingsPayloadLength)?;
    Ok(FramePayload::Settings { ack, settings })
}

fn parse_ping_frame(header: &FrameHeader, payload: &[u8]) -> Result<FramePayload, Http2FrameError> {
    let ack = (header.flags & 0x1) != 0;
    if payload.len() != 8 {
        return Err(Http2FrameError::InvalidPingPayloadLength {
            actual: payload.len(),
        });
    }
    let mut opaque = [0u8; 8];
    opaque.copy_from_slice(payload);
    Ok(FramePayload::Ping { ack, opaque })
}

fn parse_goaway_frame(
    _header: &FrameHeader,
    payload: &[u8],
) -> Result<FramePayload, Http2FrameError> {
    if payload.len() < 8 {
        return Err(Http2FrameError::InvalidGoAwayPayloadLength {
            actual: payload.len(),
        });
    }
    let last_stream_id_raw = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
    if (last_stream_id_raw & 0x8000_0000) != 0 {
        return Err(Http2FrameError::ReservedBitSetInGoAwayLastStreamId);
    }
    let last_stream_id = StreamId(last_stream_id_raw);
    let error_code = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
    let debug_data = payload[8..].to_vec();
    Ok(FramePayload::GoAway {
        last_stream_id,
        error_code,
        debug_data,
    })
}

fn parse_window_update_frame(
    _header: &FrameHeader,
    payload: &[u8],
) -> Result<FramePayload, Http2FrameError> {
    if payload.len() != 4 {
        return Err(Http2FrameError::InvalidWindowUpdatePayloadLength {
            actual: payload.len(),
        });
    }
    let raw = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
    if (raw & 0x8000_0000) != 0 {
        return Err(Http2FrameError::ReservedBitSetInWindowUpdate);
    }
    Ok(FramePayload::WindowUpdate {
        window_size_increment: raw,
    })
}

fn parse_rst_stream_frame(
    _header: &FrameHeader,
    payload: &[u8],
) -> Result<FramePayload, Http2FrameError> {
    if payload.len() != 4 {
        return Err(Http2FrameError::InvalidRstStreamPayloadLength {
            actual: payload.len(),
        });
    }
    let error_code = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
    Ok(FramePayload::RstStream { error_code })
}

fn serialize_payload(flags: u8, payload: &FramePayload) -> Result<Vec<u8>, Http2FrameError> {
    Ok(match payload {
        FramePayload::Data(b) => serialize_data_payload(flags, b)?,
        FramePayload::Headers(b)
        | FramePayload::Priority(b)
        | FramePayload::PushPromise(b)
        | FramePayload::Continuation(b) => b.clone(),
        FramePayload::RstStream { error_code } => error_code.to_be_bytes().to_vec(),
        FramePayload::Settings { ack, settings } => {
            if *ack {
                if !settings.entries.is_empty() {
                    return Err(Http2FrameError::InvalidSettingsAckPayload);
                }
                Vec::new()
            } else {
                settings.encode()
            }
        }
        FramePayload::Ping { ack: _, opaque } => opaque.to_vec(),
        FramePayload::GoAway {
            last_stream_id,
            error_code,
            debug_data,
        } => {
            let mut out = Vec::with_capacity(8 + debug_data.len());
            out.extend_from_slice(&last_stream_id.as_u32().to_be_bytes());
            out.extend_from_slice(&error_code.to_be_bytes());
            out.extend_from_slice(debug_data);
            out
        }
        FramePayload::WindowUpdate {
            window_size_increment,
        } => window_size_increment.to_be_bytes().to_vec(),
    })
}
