use crate::error::HpackError;
use crate::huffman;
use crate::integer::{decode_integer, encode_integer};

pub fn decode_string(input: &[u8], cursor: &mut usize) -> Result<Vec<u8>, HpackError> {
    if *cursor >= input.len() {
        return Err(HpackError::UnexpectedEof);
    }
    let first = input[*cursor];
    *cursor += 1;
    let is_huffman = (first & 0x80) != 0;

    let len = decode_integer(first, 7, input, cursor)? as usize;
    let remaining = input.len().saturating_sub(*cursor);
    if len > remaining {
        return Err(HpackError::InvalidStringLength {
            declared: len,
            remaining,
        });
    }

    let bytes = &input[*cursor..*cursor + len];
    *cursor += len;
    if is_huffman {
        huffman::decode(bytes)
    } else {
        Ok(bytes.to_vec())
    }
}

pub fn encode_string(bytes: &[u8], use_huffman: bool, out: &mut Vec<u8>) {
    if use_huffman {
        let encoded = huffman::encode(bytes);
        encode_integer(encoded.len() as u32, 7, 0x80, out);
        out.extend_from_slice(&encoded);
    } else {
        encode_integer(bytes.len() as u32, 7, 0x00, out);
        out.extend_from_slice(bytes);
    }
}
