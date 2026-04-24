use crate::frames::Http2FrameError;

pub const FLAG_END_STREAM: u8 = 0x1;
pub const FLAG_PADDED: u8 = 0x8;

pub fn parse_data_payload(flags: u8, payload: &[u8]) -> Result<Vec<u8>, Http2FrameError> {
    if (flags & FLAG_PADDED) == 0 {
        return Ok(payload.to_vec());
    }

    if payload.is_empty() {
        return Err(Http2FrameError::InvalidDataPadding {
            pad_length: 0,
            payload_length: 0,
        });
    }

    let pad_length = payload[0] as usize;
    if pad_length > payload.len() - 1 {
        return Err(Http2FrameError::InvalidDataPadding {
            pad_length: payload[0],
            payload_length: payload.len(),
        });
    }

    let data_end = payload.len() - pad_length;
    Ok(payload[1..data_end].to_vec())
}

pub fn serialize_data_payload(flags: u8, data: &[u8]) -> Result<Vec<u8>, Http2FrameError> {
    if (flags & FLAG_PADDED) != 0 {
        return Err(Http2FrameError::UnsupportedDataPaddingOnSerialize);
    }
    Ok(data.to_vec())
}
