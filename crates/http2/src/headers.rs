use fingerprint_proxy_core::error::{FpError, FpResult};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderField {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Copy)]
pub struct HeaderBlockInput<'a> {
    pub first_fragment: &'a [u8],
    pub continuation_fragments: &'a [&'a [u8]],
}

pub fn decode_header_block(
    decoder: &mut fingerprint_proxy_hpack::Decoder,
    input: HeaderBlockInput<'_>,
) -> FpResult<Vec<HeaderField>> {
    let mut block = Vec::with_capacity(
        input.first_fragment.len()
            + input
                .continuation_fragments
                .iter()
                .map(|f| f.len())
                .sum::<usize>(),
    );
    block.extend_from_slice(input.first_fragment);
    for frag in input.continuation_fragments {
        block.extend_from_slice(frag);
    }

    let decoded = decoder
        .decode(&block)
        .map_err(|e| FpError::invalid_protocol_data(format!("HPACK decode error: {e}")))?;

    let mut out = Vec::with_capacity(decoded.len());
    for field in decoded {
        let name_bytes = field.name;
        if name_bytes.is_empty() {
            return Err(FpError::invalid_protocol_data(
                "HTTP/2 header name must be non-empty",
            ));
        }
        if name_bytes.iter().any(|b| b.is_ascii_uppercase()) {
            return Err(FpError::invalid_protocol_data(
                "HTTP/2 header name must be lowercase",
            ));
        }

        let name = String::from_utf8(name_bytes).map_err(|_| {
            FpError::invalid_protocol_data("HTTP/2 header name must be valid UTF-8")
        })?;
        let value = String::from_utf8(field.value).map_err(|_| {
            FpError::invalid_protocol_data("HTTP/2 header value must be valid UTF-8")
        })?;
        out.push(HeaderField { name, value });
    }

    Ok(out)
}
