use crate::headers::HeaderField;
use crate::varint::{decode_varint, encode_varint, map_varint_error};
use fingerprint_proxy_core::error::{FpError, FpResult};

const LITERAL_FIELD_WITH_LITERAL_NAME: u8 = 0x00;

/// Encodes an HTTP/3 header block using a bounded static QPACK subset.
///
/// Supported representation:
/// - Literal field line with literal name (0x00), followed by
///   varint(name_len), name bytes, varint(value_len), value bytes.
///
/// Dynamic/static table references and other QPACK field-line encodings are
/// intentionally unsupported in this bounded runtime slice and must fail
/// deterministically on decode.
pub fn encode_header_block(fields: &[HeaderField]) -> FpResult<Vec<u8>> {
    let mut out = Vec::new();
    for field in fields {
        out.push(LITERAL_FIELD_WITH_LITERAL_NAME);
        append_len_prefixed(&mut out, field.name.as_bytes())?;
        append_len_prefixed(&mut out, field.value.as_bytes())?;
    }
    Ok(out)
}

/// Decodes an HTTP/3 header block using the same bounded static QPACK subset
/// supported by `encode_header_block`.
pub fn decode_header_block(raw: &[u8]) -> FpResult<Vec<HeaderField>> {
    let mut out = Vec::new();
    let mut offset = 0usize;

    while offset < raw.len() {
        let field_prefix = raw[offset];
        offset += 1;

        if field_prefix != LITERAL_FIELD_WITH_LITERAL_NAME {
            return Err(FpError::invalid_protocol_data(
                "HTTP/3 QPACK decode supports only literal field lines with literal names",
            ));
        }

        let name = decode_len_prefixed_utf8(raw, &mut offset, "HTTP/3 QPACK decode name")?;
        let value = decode_len_prefixed_utf8(raw, &mut offset, "HTTP/3 QPACK decode value")?;
        out.push(HeaderField { name, value });
    }

    Ok(out)
}

fn append_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) -> FpResult<()> {
    let len = u64::try_from(bytes.len())
        .map_err(|_| FpError::invalid_protocol_data("HTTP/3 QPACK encode length out of range"))?;
    out.extend_from_slice(
        &encode_varint(len).map_err(|e| map_varint_error("HTTP/3 QPACK encode length", e))?,
    );
    out.extend_from_slice(bytes);
    Ok(())
}

fn decode_len_prefixed_utf8(
    input: &[u8],
    offset: &mut usize,
    context: &'static str,
) -> FpResult<String> {
    let (len, used) = decode_varint(&input[*offset..]).map_err(|e| map_varint_error(context, e))?;
    *offset += used;

    let len = usize::try_from(len)
        .map_err(|_| FpError::invalid_protocol_data(format!("{context}: length too large")))?;
    let end = offset
        .checked_add(len)
        .ok_or_else(|| FpError::invalid_protocol_data(format!("{context}: length overflow")))?;
    if end > input.len() {
        return Err(FpError::invalid_protocol_data(format!(
            "{context}: truncated bytes",
        )));
    }

    let s = std::str::from_utf8(&input[*offset..end])
        .map_err(|_| FpError::invalid_protocol_data(format!("{context}: invalid UTF-8")))?;
    *offset = end;
    Ok(s.to_string())
}
