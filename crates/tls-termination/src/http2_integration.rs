use fingerprint_proxy_core::error::{FpError, FpResult};
use fingerprint_proxy_http2::frames::{parse_frame, Frame, Http2FrameError};
use fingerprint_proxy_http2::ConnectionPreface;

#[derive(Debug, Default)]
pub struct Http2ProtocolParser {
    buffer: Vec<u8>,
    preface_consumed: bool,
}

impl Http2ProtocolParser {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn preface_consumed(&self) -> bool {
        self.preface_consumed
    }

    pub fn pending_bytes(&self) -> usize {
        self.buffer.len()
    }

    pub fn push_bytes(&mut self, bytes: &[u8]) -> FpResult<Vec<Frame>> {
        self.buffer.extend_from_slice(bytes);

        if !self.preface_consumed {
            let preface = ConnectionPreface::CLIENT_BYTES.as_slice();
            if self.buffer.len() < preface.len() {
                if !preface.starts_with(&self.buffer) {
                    return Err(FpError::invalid_protocol_data(
                        "HTTP/2 connection preface mismatch",
                    ));
                }
                return Ok(Vec::new());
            }
            if !self.buffer.starts_with(preface) {
                return Err(FpError::invalid_protocol_data(
                    "HTTP/2 connection preface mismatch",
                ));
            }
            self.buffer.drain(0..preface.len());
            self.preface_consumed = true;
        }

        let mut frames = Vec::new();
        let mut offset = 0usize;
        loop {
            match parse_frame(&self.buffer[offset..]) {
                Ok((frame, consumed)) => {
                    offset += consumed;
                    frames.push(frame);
                }
                Err(Http2FrameError::UnexpectedEof) => break,
                Err(err) => {
                    return Err(FpError::invalid_protocol_data(format!(
                        "HTTP/2 frame decode error: {err}"
                    )));
                }
            }
        }

        if offset > 0 {
            self.buffer.drain(0..offset);
        }
        Ok(frames)
    }
}
