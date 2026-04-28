use fingerprint_proxy_core::error::{FpError, FpResult};

const BASIC_HEADER_LEN: usize = 2;
const MASK_KEY_LEN: usize = 4;
const PAYLOAD_16_MARKER: u8 = 126;
const PAYLOAD_64_MARKER: u8 = 127;
const FIN_MASK: u8 = 0b1000_0000;
const RSV_MASK: u8 = 0b0111_0000;
const OPCODE_MASK: u8 = 0b0000_1111;
const MASKED_MASK: u8 = 0b1000_0000;
const PAYLOAD_LEN_MASK: u8 = 0b0111_1111;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebSocketOpcode {
    Continuation,
    Text,
    Binary,
    Close,
    Ping,
    Pong,
}

impl WebSocketOpcode {
    fn from_u8(value: u8) -> FpResult<Self> {
        match value {
            0x0 => Ok(Self::Continuation),
            0x1 => Ok(Self::Text),
            0x2 => Ok(Self::Binary),
            0x8 => Ok(Self::Close),
            0x9 => Ok(Self::Ping),
            0xA => Ok(Self::Pong),
            _ => Err(FpError::invalid_protocol_data(
                "WebSocket frame parse failed: unsupported opcode",
            )),
        }
    }

    fn is_control(self) -> bool {
        matches!(self, Self::Close | Self::Ping | Self::Pong)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebSocketFrame {
    pub fin: bool,
    pub opcode: WebSocketOpcode,
    pub masked: bool,
    pub payload: Vec<u8>,
}

pub fn parse_websocket_frames(input: &[u8]) -> FpResult<Vec<WebSocketFrame>> {
    let mut frames = Vec::new();
    let mut offset = 0usize;

    while offset < input.len() {
        let (frame, consumed) = match parse_websocket_frame_prefix_detailed(&input[offset..], None)?
        {
            FramePrefixParse::Complete { frame, consumed } => (frame, consumed),
            FramePrefixParse::NeedMore(message) => {
                return Err(FpError::invalid_protocol_data(message));
            }
        };
        offset += consumed;
        frames.push(frame);
    }

    Ok(frames)
}

pub fn parse_websocket_frame_prefix(input: &[u8]) -> FpResult<Option<(WebSocketFrame, usize)>> {
    parse_websocket_frame_prefix_with_limit(input, None)
}

pub fn parse_websocket_frame_prefix_with_max_payload(
    input: &[u8],
    max_payload_bytes: usize,
) -> FpResult<Option<(WebSocketFrame, usize)>> {
    parse_websocket_frame_prefix_with_limit(input, Some(max_payload_bytes))
}

fn parse_websocket_frame_prefix_with_limit(
    input: &[u8],
    max_payload_bytes: Option<usize>,
) -> FpResult<Option<(WebSocketFrame, usize)>> {
    match parse_websocket_frame_prefix_detailed(input, max_payload_bytes)? {
        FramePrefixParse::Complete { frame, consumed } => Ok(Some((frame, consumed))),
        FramePrefixParse::NeedMore(_) => Ok(None),
    }
}

enum FramePrefixParse {
    Complete {
        frame: WebSocketFrame,
        consumed: usize,
    },
    NeedMore(&'static str),
}

fn parse_websocket_frame_prefix_detailed(
    input: &[u8],
    max_payload_bytes: Option<usize>,
) -> FpResult<FramePrefixParse> {
    if input.len() < BASIC_HEADER_LEN {
        return Ok(FramePrefixParse::NeedMore(
            "WebSocket frame parse failed: truncated frame header",
        ));
    }

    let mut offset = 0usize;
    let first = input[offset];
    let second = input[offset + 1];
    offset += BASIC_HEADER_LEN;

    if first & RSV_MASK != 0 {
        return Err(FpError::invalid_protocol_data(
            "WebSocket frame parse failed: reserved bits are not supported",
        ));
    }

    let fin = first & FIN_MASK != 0;
    let opcode = WebSocketOpcode::from_u8(first & OPCODE_MASK)?;
    if opcode.is_control() && !fin {
        return Err(FpError::invalid_protocol_data(
            "WebSocket frame parse failed: fragmented control frames are invalid",
        ));
    }

    let masked = second & MASKED_MASK != 0;
    let mut payload_len = usize::from(second & PAYLOAD_LEN_MASK);

    if payload_len == usize::from(PAYLOAD_16_MARKER) {
        if input.len() - offset < 2 {
            return Ok(FramePrefixParse::NeedMore(
                "WebSocket frame parse failed: truncated extended payload length",
            ));
        }
        payload_len = usize::from(u16::from_be_bytes([input[offset], input[offset + 1]]));
        offset += 2;
    } else if payload_len == usize::from(PAYLOAD_64_MARKER) {
        if input.len() - offset < 8 {
            return Ok(FramePrefixParse::NeedMore(
                "WebSocket frame parse failed: truncated extended payload length",
            ));
        }
        let len = u64::from_be_bytes([
            input[offset],
            input[offset + 1],
            input[offset + 2],
            input[offset + 3],
            input[offset + 4],
            input[offset + 5],
            input[offset + 6],
            input[offset + 7],
        ]);
        payload_len = usize::try_from(len).map_err(|_| {
            FpError::invalid_protocol_data(
                "WebSocket frame parse failed: payload length does not fit in memory",
            )
        })?;
        offset += 8;
    }

    if opcode.is_control() && payload_len > 125 {
        return Err(FpError::invalid_protocol_data(
            "WebSocket frame parse failed: control frame payload exceeds 125 bytes",
        ));
    }
    if let Some(max_payload_bytes) = max_payload_bytes {
        if payload_len > max_payload_bytes {
            return Err(FpError::invalid_protocol_data(format!(
                "WebSocket frame parse failed: payload length {payload_len} exceeds configured maximum {max_payload_bytes}"
            )));
        }
    }

    let mask_key = if masked {
        if input.len() - offset < MASK_KEY_LEN {
            return Ok(FramePrefixParse::NeedMore(
                "WebSocket frame parse failed: truncated masking key",
            ));
        }
        let key = [
            input[offset],
            input[offset + 1],
            input[offset + 2],
            input[offset + 3],
        ];
        offset += MASK_KEY_LEN;
        Some(key)
    } else {
        None
    };

    if input.len() - offset < payload_len {
        return Ok(FramePrefixParse::NeedMore(
            "WebSocket frame parse failed: truncated payload",
        ));
    }

    let mut payload = input[offset..offset + payload_len].to_vec();
    offset += payload_len;

    if let Some(mask_key) = mask_key {
        for (idx, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask_key[idx % MASK_KEY_LEN];
        }
    }

    Ok(FramePrefixParse::Complete {
        frame: WebSocketFrame {
            fin,
            opcode,
            masked,
            payload,
        },
        consumed: offset,
    })
}
