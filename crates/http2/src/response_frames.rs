use crate::frames::{Frame, FrameHeader, FramePayload, FrameType};
use crate::streams::StreamId;
use fingerprint_proxy_core::error::{FpError, FpResult};
use fingerprint_proxy_core::request::HttpResponse;

const FLAG_END_STREAM: u8 = 0x1;
const FLAG_END_HEADERS: u8 = 0x4;
const DEFAULT_MAX_FRAME_PAYLOAD_BYTES: usize = 16_384;

pub fn encode_http2_response_frames(
    encoder: &mut fingerprint_proxy_hpack::Encoder,
    stream_id: StreamId,
    resp: &HttpResponse,
) -> FpResult<Vec<Frame>> {
    if stream_id.is_connection() {
        return Err(FpError::invalid_protocol_data(
            "HTTP/2 response frames require a non-zero stream_id",
        ));
    }

    let header_block = crate::encode_http2_response_headers(encoder, resp)?;

    let has_body = !resp.body.is_empty();
    let has_trailers = !resp.trailers.is_empty();
    let headers_flags = if has_body || has_trailers {
        FLAG_END_HEADERS
    } else {
        FLAG_END_HEADERS | FLAG_END_STREAM
    };

    let mut frames = Vec::new();
    frames.push(Frame {
        header: FrameHeader {
            length: header_block.len() as u32,
            frame_type: FrameType::Headers,
            flags: headers_flags,
            stream_id,
        },
        payload: FramePayload::Headers(header_block),
    });

    if has_body {
        for (index, chunk) in resp
            .body
            .chunks(DEFAULT_MAX_FRAME_PAYLOAD_BYTES)
            .enumerate()
        {
            let is_final_chunk = (index + 1) * DEFAULT_MAX_FRAME_PAYLOAD_BYTES >= resp.body.len();
            let payload = chunk.to_vec();
            frames.push(Frame {
                header: FrameHeader {
                    length: payload.len() as u32,
                    frame_type: FrameType::Data,
                    flags: if is_final_chunk && !has_trailers {
                        FLAG_END_STREAM
                    } else {
                        0
                    },
                    stream_id,
                },
                payload: FramePayload::Data(payload),
            });
        }
    }

    if has_trailers {
        let trailer_block = encode_http2_trailers(encoder, &resp.trailers)?;
        frames.push(Frame {
            header: FrameHeader {
                length: trailer_block.len() as u32,
                frame_type: FrameType::Headers,
                flags: FLAG_END_HEADERS | FLAG_END_STREAM,
                stream_id,
            },
            payload: FramePayload::Headers(trailer_block),
        });
    }

    Ok(frames)
}

fn encode_http2_trailers(
    encoder: &mut fingerprint_proxy_hpack::Encoder,
    trailers: &std::collections::BTreeMap<String, String>,
) -> FpResult<Vec<u8>> {
    let mut out = Vec::new();

    for (name, value) in trailers {
        if name.is_empty() {
            return Err(FpError::invalid_protocol_data(
                "HTTP/2 trailer header name must be non-empty",
            ));
        }
        if name.starts_with(':') {
            return Err(FpError::invalid_protocol_data(
                "HTTP/2 trailers must not contain pseudo-headers",
            ));
        }
        if name.as_bytes().iter().any(|b| b.is_ascii_uppercase()) {
            return Err(FpError::invalid_protocol_data(
                "HTTP/2 trailer header name must be lowercase",
            ));
        }
        if is_connection_specific_header(name.as_str()) {
            return Err(FpError::invalid_protocol_data(
                "HTTP/2 connection-specific header is not allowed",
            ));
        }

        let field = fingerprint_proxy_hpack::HeaderField {
            name: name.as_bytes().to_vec(),
            value: value.as_bytes().to_vec(),
        };
        out.extend_from_slice(&encoder.encode_literal_without_indexing(&field));
    }

    Ok(out)
}

fn is_connection_specific_header(name: &str) -> bool {
    matches!(
        name,
        "connection" | "proxy-connection" | "keep-alive" | "transfer-encoding" | "upgrade"
    )
}
