use crate::frames::{Frame, FrameType};
use fingerprint_proxy_core::error::FpError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamEvent {
    RequestHeadersReady(Vec<u8>),
    RequestComplete {
        headers: Vec<u8>,
        trailers: Option<Vec<u8>>,
        body: Vec<u8>,
    },
}

#[derive(Debug, Clone)]
enum AssemblerState {
    WaitingForHeaders,
    WaitingForFin {
        headers: Vec<u8>,
        trailers: Option<Vec<u8>>,
        body: Vec<u8>,
        saw_data: bool,
    },
    Closed,
}

#[derive(Debug, Clone)]
pub struct Http3RequestStreamAssembler {
    state: AssemblerState,
}

impl Default for Http3RequestStreamAssembler {
    fn default() -> Self {
        Self::new()
    }
}

impl Http3RequestStreamAssembler {
    pub fn new() -> Self {
        Self {
            state: AssemblerState::WaitingForHeaders,
        }
    }

    pub fn push_frame(&mut self, frame: Frame) -> Result<Vec<StreamEvent>, FpError> {
        match (&mut self.state, frame.frame_type) {
            (AssemblerState::Closed, _) => {
                Err(FpError::invalid_protocol_data("HTTP/3 stream is closed"))
            }
            (AssemblerState::WaitingForHeaders, FrameType::Headers) => {
                let headers = frame.payload_bytes().to_vec();
                self.state = AssemblerState::WaitingForFin {
                    headers: headers.clone(),
                    trailers: None,
                    body: Vec::new(),
                    saw_data: false,
                };
                Ok(vec![StreamEvent::RequestHeadersReady(headers)])
            }
            (AssemblerState::WaitingForHeaders, FrameType::Data) => Err(
                FpError::invalid_protocol_data("HTTP/3 DATA received before HEADERS"),
            ),
            (AssemblerState::WaitingForHeaders, _) => Err(FpError::invalid_protocol_data(
                "HTTP/3 unexpected frame before HEADERS",
            )),
            (
                AssemblerState::WaitingForFin {
                    trailers: Some(_), ..
                },
                FrameType::Headers,
            ) => Err(FpError::invalid_protocol_data(
                "HTTP/3 multiple trailers HEADERS frames are not supported",
            )),
            (
                AssemblerState::WaitingForFin {
                    saw_data: false, ..
                },
                FrameType::Headers,
            ) => Err(FpError::invalid_protocol_data(
                "HTTP/3 trailers HEADERS must appear after DATA",
            )),
            (AssemblerState::WaitingForFin { trailers: None, .. }, FrameType::Headers) => {
                let trailers = frame.payload_bytes().to_vec();
                if let AssemblerState::WaitingForFin { trailers: t, .. } = &mut self.state {
                    *t = Some(trailers);
                }
                Ok(Vec::new())
            }
            (
                AssemblerState::WaitingForFin {
                    trailers: Some(_), ..
                },
                FrameType::Data,
            ) => Err(FpError::invalid_protocol_data(
                "HTTP/3 DATA is not allowed after trailers",
            )),
            (AssemblerState::WaitingForFin { body, saw_data, .. }, FrameType::Data) => {
                body.extend_from_slice(frame.payload_bytes());
                *saw_data = true;
                Ok(Vec::new())
            }
            (AssemblerState::WaitingForFin { .. }, FrameType::Settings) => Err(
                FpError::invalid_protocol_data("HTTP/3 SETTINGS is not valid on request streams"),
            ),
            (AssemblerState::WaitingForFin { .. }, _) => Err(FpError::invalid_protocol_data(
                "HTTP/3 unsupported frame on request stream",
            )),
        }
    }

    pub fn finish_stream(&mut self) -> Result<Vec<StreamEvent>, FpError> {
        match std::mem::replace(&mut self.state, AssemblerState::Closed) {
            AssemblerState::WaitingForHeaders => Err(FpError::invalid_protocol_data(
                "HTTP/3 stream finished before HEADERS",
            )),
            AssemblerState::WaitingForFin {
                headers,
                trailers,
                body,
                saw_data: _,
            } => Ok(vec![StreamEvent::RequestComplete {
                headers,
                trailers,
                body,
            }]),
            AssemblerState::Closed => {
                Err(FpError::invalid_protocol_data("HTTP/3 stream is closed"))
            }
        }
    }
}
