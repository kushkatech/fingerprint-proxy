use fingerprint_proxy_core::error::FpError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VarintError {
    UnexpectedEof,
    ValueOutOfRange,
}

pub fn decode_varint(input: &[u8]) -> Result<(u64, usize), VarintError> {
    let Some(&first) = input.first() else {
        return Err(VarintError::UnexpectedEof);
    };

    let prefix = first >> 6;
    let len = match prefix {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        _ => unreachable!(),
    };

    if input.len() < len {
        return Err(VarintError::UnexpectedEof);
    }

    let mut v: u64 = (first & 0x3f) as u64;
    for &b in &input[1..len] {
        v = (v << 8) | (b as u64);
    }

    Ok((v, len))
}

pub fn encode_varint(value: u64) -> Result<Vec<u8>, VarintError> {
    if value <= 63 {
        return Ok(vec![value as u8]);
    }
    if value <= 16383 {
        let v = value as u16;
        let b0 = 0x40 | (((v >> 8) & 0x3f) as u8);
        let b1 = (v & 0xff) as u8;
        return Ok(vec![b0, b1]);
    }
    if value <= 1_073_741_823 {
        let v = value as u32;
        let b0 = 0x80 | (((v >> 24) & 0x3f) as u8);
        let b1 = ((v >> 16) & 0xff) as u8;
        let b2 = ((v >> 8) & 0xff) as u8;
        let b3 = (v & 0xff) as u8;
        return Ok(vec![b0, b1, b2, b3]);
    }
    if value <= 4_611_686_018_427_387_903 {
        let v = value;
        let b0 = 0xC0 | (((v >> 56) & 0x3f) as u8);
        let b1 = ((v >> 48) & 0xff) as u8;
        let b2 = ((v >> 40) & 0xff) as u8;
        let b3 = ((v >> 32) & 0xff) as u8;
        let b4 = ((v >> 24) & 0xff) as u8;
        let b5 = ((v >> 16) & 0xff) as u8;
        let b6 = ((v >> 8) & 0xff) as u8;
        let b7 = (v & 0xff) as u8;
        return Ok(vec![b0, b1, b2, b3, b4, b5, b6, b7]);
    }

    Err(VarintError::ValueOutOfRange)
}

pub fn map_varint_error(context: &'static str, err: VarintError) -> FpError {
    match err {
        VarintError::UnexpectedEof => {
            FpError::invalid_protocol_data(format!("{context}: truncated varint"))
        }
        VarintError::ValueOutOfRange => {
            FpError::invalid_protocol_data(format!("{context}: varint value out of range"))
        }
    }
}
