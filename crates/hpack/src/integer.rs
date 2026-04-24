use crate::error::HpackError;

pub fn decode_integer(
    first_byte: u8,
    prefix_bits: u8,
    input: &[u8],
    cursor: &mut usize,
) -> Result<u32, HpackError> {
    let prefix_mask: u8 = if prefix_bits == 8 {
        0xff
    } else {
        (1u16
            .checked_shl(prefix_bits.into())
            .ok_or(HpackError::InvalidIntegerEncoding)? as u8)
            .wrapping_sub(1)
    };

    let mut value = u32::from(first_byte & prefix_mask);
    if value < u32::from(prefix_mask) {
        return Ok(value);
    }

    let mut m: u32 = 0;
    loop {
        if *cursor >= input.len() {
            return Err(HpackError::UnexpectedEof);
        }
        let b = input[*cursor];
        *cursor += 1;
        let add = u32::from(b & 0x7f)
            .checked_shl(m)
            .ok_or(HpackError::IntegerOverflow)?;
        value = value.checked_add(add).ok_or(HpackError::IntegerOverflow)?;
        if (b & 0x80) == 0 {
            break;
        }
        m = m.checked_add(7).ok_or(HpackError::IntegerOverflow)?;
        if m > 28 {
            return Err(HpackError::IntegerOverflow);
        }
    }
    Ok(value)
}

pub fn encode_integer(value: u32, prefix_bits: u8, first_byte_high: u8, out: &mut Vec<u8>) {
    let prefix_max: u32 = if prefix_bits == 8 {
        255
    } else {
        (1u32 << prefix_bits) - 1
    };

    if value < prefix_max {
        out.push(first_byte_high | (value as u8));
        return;
    }

    out.push(first_byte_high | (prefix_max as u8));
    let mut rem = value - prefix_max;
    while rem >= 128 {
        out.push(((rem % 128) as u8) | 0x80);
        rem /= 128;
    }
    out.push(rem as u8);
}
