#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicVarintError {
    UnexpectedEof,
    ValueOutOfRange,
}

pub fn decode_varint(input: &[u8]) -> Result<(u64, usize), QuicVarintError> {
    let Some(&first) = input.first() else {
        return Err(QuicVarintError::UnexpectedEof);
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
        return Err(QuicVarintError::UnexpectedEof);
    }

    let mut value = (first & 0x3f) as u64;
    for &byte in &input[1..len] {
        value = (value << 8) | byte as u64;
    }

    Ok((value, len))
}

pub fn encode_varint(value: u64) -> Result<Vec<u8>, QuicVarintError> {
    if value <= 63 {
        return Ok(vec![value as u8]);
    }
    if value <= 16_383 {
        let value = value as u16;
        return Ok(vec![
            0x40 | (((value >> 8) & 0x3f) as u8),
            (value & 0xff) as u8,
        ]);
    }
    if value <= 1_073_741_823 {
        let value = value as u32;
        return Ok(vec![
            0x80 | (((value >> 24) & 0x3f) as u8),
            ((value >> 16) & 0xff) as u8,
            ((value >> 8) & 0xff) as u8,
            (value & 0xff) as u8,
        ]);
    }
    if value <= 4_611_686_018_427_387_903 {
        return Ok(vec![
            0xc0 | (((value >> 56) & 0x3f) as u8),
            ((value >> 48) & 0xff) as u8,
            ((value >> 40) & 0xff) as u8,
            ((value >> 32) & 0xff) as u8,
            ((value >> 24) & 0xff) as u8,
            ((value >> 16) & 0xff) as u8,
            ((value >> 8) & 0xff) as u8,
            (value & 0xff) as u8,
        ]);
    }

    Err(QuicVarintError::ValueOutOfRange)
}
