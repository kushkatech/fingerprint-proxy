use crate::frames::{Frame, FramePayload, FrameType};
use crate::streams::StreamId;
use fingerprint_proxy_core::error::{FpError, FpResult};
use fingerprint_proxy_core::request::HttpRequest;

const FLAG_END_STREAM: u8 = 0x1;
const FLAG_END_HEADERS: u8 = 0x4;

type StepResult = Result<(AssemblerState, Option<StreamEvent>), Box<(FpError, AssemblerState)>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamEvent {
    RequestHeadersReady(HttpRequest),
    RequestComplete(HttpRequest),
}

#[derive(Debug, Clone)]
enum AssemblerState {
    ExpectHeaders,
    CollectingHeaderBlock {
        fragments: Vec<Vec<u8>>,
        end_stream: bool,
    },
    HeadersComplete {
        request: HttpRequest,
        body: Vec<u8>,
        trailers: std::collections::BTreeMap<String, String>,
    },
    CollectingTrailerBlock {
        request: HttpRequest,
        body: Vec<u8>,
        fragments: Vec<Vec<u8>>,
    },
    Complete,
}

#[derive(Debug, Clone)]
pub struct Http2RequestStreamAssembler {
    stream_id: StreamId,
    state: AssemblerState,
}

impl Http2RequestStreamAssembler {
    pub fn new(stream_id: StreamId) -> Self {
        Self {
            stream_id,
            state: AssemblerState::ExpectHeaders,
        }
    }

    pub fn stream_id(&self) -> StreamId {
        self.stream_id
    }

    pub fn push_frame(
        &mut self,
        decoder: &mut fingerprint_proxy_hpack::Decoder,
        frame: Frame,
    ) -> FpResult<Option<StreamEvent>> {
        if frame.header.stream_id != self.stream_id {
            return Err(FpError::invalid_protocol_data(
                "HTTP/2 frame stream_id does not match stream assembler",
            ));
        }

        let prior = std::mem::replace(&mut self.state, AssemblerState::Complete);
        let res: StepResult = match prior {
            AssemblerState::ExpectHeaders => match step_expect_headers(decoder, frame) {
                Ok(v) => Ok(v),
                Err(e) => Err(Box::new((e, AssemblerState::ExpectHeaders))),
            },
            AssemblerState::CollectingHeaderBlock {
                fragments,
                end_stream,
            } => step_collecting_header_block(decoder, frame, fragments, end_stream),
            AssemblerState::HeadersComplete {
                request,
                body,
                trailers,
            } => step_headers_complete(decoder, frame, request, body, trailers),
            AssemblerState::CollectingTrailerBlock {
                request,
                body,
                fragments,
            } => step_collecting_trailer_block(decoder, frame, request, body, fragments),
            AssemblerState::Complete => Err(Box::new((
                FpError::invalid_protocol_data("HTTP/2 stream is already complete"),
                AssemblerState::Complete,
            ))),
        };

        match res {
            Ok((next, ev)) => {
                self.state = next;
                Ok(ev)
            }
            Err(e) => {
                let (e, restore) = *e;
                self.state = restore;
                Err(e)
            }
        }
    }
}

fn step_expect_headers(
    decoder: &mut fingerprint_proxy_hpack::Decoder,
    frame: Frame,
) -> FpResult<(AssemblerState, Option<StreamEvent>)> {
    if frame.header.frame_type != FrameType::Headers {
        return Err(FpError::invalid_protocol_data(
            "HTTP/2 request stream must start with HEADERS",
        ));
    }

    let end_headers = (frame.header.flags & FLAG_END_HEADERS) != 0;
    let end_stream = (frame.header.flags & FLAG_END_STREAM) != 0;

    let FramePayload::Headers(bytes) = frame.payload else {
        return Err(FpError::invalid_protocol_data(
            "HTTP/2 HEADERS frame payload mismatch",
        ));
    };

    if end_headers {
        let req = crate::decode_http2_request_headers(decoder, &bytes, &[])?;
        if end_stream {
            let mut req = req;
            req.body = Vec::new();
            req.trailers = std::collections::BTreeMap::new();
            return Ok((
                AssemblerState::Complete,
                Some(StreamEvent::RequestComplete(req)),
            ));
        }

        let req_clone = req.clone();
        return Ok((
            AssemblerState::HeadersComplete {
                request: req,
                body: Vec::new(),
                trailers: std::collections::BTreeMap::new(),
            },
            Some(StreamEvent::RequestHeadersReady(req_clone)),
        ));
    }

    Ok((
        AssemblerState::CollectingHeaderBlock {
            fragments: vec![bytes],
            end_stream,
        },
        None,
    ))
}

fn step_collecting_header_block(
    decoder: &mut fingerprint_proxy_hpack::Decoder,
    frame: Frame,
    mut fragments: Vec<Vec<u8>>,
    mut end_stream: bool,
) -> StepResult {
    match frame.header.frame_type {
        FrameType::Continuation => {}
        FrameType::Data => {
            return Err(Box::new((
                FpError::invalid_protocol_data("HTTP/2 DATA is not allowed before END_HEADERS"),
                AssemblerState::CollectingHeaderBlock {
                    fragments,
                    end_stream,
                },
            )));
        }
        _ => {
            return Err(Box::new((
                FpError::invalid_protocol_data(
                    "HTTP/2 unexpected frame type while awaiting CONTINUATION",
                ),
                AssemblerState::CollectingHeaderBlock {
                    fragments,
                    end_stream,
                },
            )));
        }
    }

    let end_headers = (frame.header.flags & FLAG_END_HEADERS) != 0;
    if (frame.header.flags & FLAG_END_STREAM) != 0 {
        end_stream = true;
    }

    let FramePayload::Continuation(bytes) = frame.payload else {
        return Err(Box::new((
            FpError::invalid_protocol_data("HTTP/2 CONTINUATION frame payload mismatch"),
            AssemblerState::CollectingHeaderBlock {
                fragments,
                end_stream,
            },
        )));
    };
    fragments.push(bytes);

    if !end_headers {
        return Ok((
            AssemblerState::CollectingHeaderBlock {
                fragments,
                end_stream,
            },
            None,
        ));
    }

    if fragments.is_empty() {
        return Err(Box::new((
            FpError::internal("missing initial header fragment"),
            AssemblerState::CollectingHeaderBlock {
                fragments,
                end_stream,
            },
        )));
    }

    let cont_refs: Vec<&[u8]> = fragments.iter().skip(1).map(|f| f.as_slice()).collect();
    let req =
        crate::decode_http2_request_headers(decoder, &fragments[0], &cont_refs).map_err(|e| {
            Box::new((
                e,
                AssemblerState::CollectingHeaderBlock {
                    fragments,
                    end_stream,
                },
            ))
        })?;

    if end_stream {
        let mut req = req;
        req.body = Vec::new();
        req.trailers = std::collections::BTreeMap::new();
        return Ok((
            AssemblerState::Complete,
            Some(StreamEvent::RequestComplete(req)),
        ));
    }

    let req_clone = req.clone();
    Ok((
        AssemblerState::HeadersComplete {
            request: req,
            body: Vec::new(),
            trailers: std::collections::BTreeMap::new(),
        },
        Some(StreamEvent::RequestHeadersReady(req_clone)),
    ))
}

fn step_headers_complete(
    decoder: &mut fingerprint_proxy_hpack::Decoder,
    frame: Frame,
    mut request: HttpRequest,
    mut body: Vec<u8>,
    mut trailers: std::collections::BTreeMap<String, String>,
) -> StepResult {
    match frame.header.frame_type {
        FrameType::Data => {}
        FrameType::Continuation => {
            return Err(Box::new((
                FpError::invalid_protocol_data(
                    "HTTP/2 CONTINUATION is not allowed after END_HEADERS",
                ),
                AssemblerState::HeadersComplete {
                    request,
                    body,
                    trailers,
                },
            )));
        }
        FrameType::Headers => {
            let end_headers = (frame.header.flags & FLAG_END_HEADERS) != 0;
            let end_stream = (frame.header.flags & FLAG_END_STREAM) != 0;
            if !end_stream {
                return Err(Box::new((
                    FpError::invalid_protocol_data("HTTP/2 trailers HEADERS must set END_STREAM"),
                    AssemblerState::HeadersComplete {
                        request,
                        body,
                        trailers,
                    },
                )));
            }

            let FramePayload::Headers(bytes) = frame.payload else {
                return Err(Box::new((
                    FpError::invalid_protocol_data("HTTP/2 HEADERS frame payload mismatch"),
                    AssemblerState::HeadersComplete {
                        request,
                        body,
                        trailers,
                    },
                )));
            };

            if end_headers {
                let parsed = match decode_trailers(decoder, &bytes, &[]) {
                    Ok(v) => v,
                    Err(e) => {
                        return Err(Box::new((
                            e,
                            AssemblerState::HeadersComplete {
                                request,
                                body,
                                trailers,
                            },
                        )))
                    }
                };
                trailers.extend(parsed);
                request.body = body;
                request.trailers = trailers;
                return Ok((
                    AssemblerState::Complete,
                    Some(StreamEvent::RequestComplete(request)),
                ));
            }

            return Ok((
                AssemblerState::CollectingTrailerBlock {
                    request,
                    body,
                    fragments: vec![bytes],
                },
                None,
            ));
        }
        _ => {
            return Err(Box::new((
                FpError::invalid_protocol_data(
                    "HTTP/2 unexpected frame type after headers are complete",
                ),
                AssemblerState::HeadersComplete {
                    request,
                    body,
                    trailers,
                },
            )));
        }
    }

    let FramePayload::Data(bytes) = frame.payload else {
        return Err(Box::new((
            FpError::invalid_protocol_data("HTTP/2 DATA frame payload mismatch"),
            AssemblerState::HeadersComplete {
                request,
                body,
                trailers,
            },
        )));
    };
    body.extend_from_slice(&bytes);

    let frame_end_stream = (frame.header.flags & FLAG_END_STREAM) != 0;
    if frame_end_stream {
        request.body = body;
        request.trailers = trailers;
        return Ok((
            AssemblerState::Complete,
            Some(StreamEvent::RequestComplete(request)),
        ));
    }

    Ok((
        AssemblerState::HeadersComplete {
            request,
            body,
            trailers,
        },
        None,
    ))
}

fn step_collecting_trailer_block(
    decoder: &mut fingerprint_proxy_hpack::Decoder,
    frame: Frame,
    mut request: HttpRequest,
    body: Vec<u8>,
    mut fragments: Vec<Vec<u8>>,
) -> StepResult {
    match frame.header.frame_type {
        FrameType::Continuation => {}
        FrameType::Data => {
            return Err(Box::new((
                FpError::invalid_protocol_data(
                    "HTTP/2 DATA is not allowed after starting trailers",
                ),
                AssemblerState::CollectingTrailerBlock {
                    request,
                    body,
                    fragments,
                },
            )));
        }
        FrameType::Headers => {
            return Err(Box::new((
                FpError::invalid_protocol_data(
                    "HTTP/2 multiple trailers HEADERS blocks are not supported",
                ),
                AssemblerState::CollectingTrailerBlock {
                    request,
                    body,
                    fragments,
                },
            )));
        }
        _ => {
            return Err(Box::new((
                FpError::invalid_protocol_data(
                    "HTTP/2 unexpected frame type while awaiting trailer CONTINUATION",
                ),
                AssemblerState::CollectingTrailerBlock {
                    request,
                    body,
                    fragments,
                },
            )));
        }
    }

    let end_headers = (frame.header.flags & FLAG_END_HEADERS) != 0;
    if (frame.header.flags & FLAG_END_STREAM) != 0 {
        return Err(Box::new((
            FpError::invalid_protocol_data("HTTP/2 CONTINUATION must not set END_STREAM"),
            AssemblerState::CollectingTrailerBlock {
                request,
                body,
                fragments,
            },
        )));
    }

    let FramePayload::Continuation(bytes) = frame.payload else {
        return Err(Box::new((
            FpError::invalid_protocol_data("HTTP/2 CONTINUATION frame payload mismatch"),
            AssemblerState::CollectingTrailerBlock {
                request,
                body,
                fragments,
            },
        )));
    };
    fragments.push(bytes);

    if !end_headers {
        return Ok((
            AssemblerState::CollectingTrailerBlock {
                request,
                body,
                fragments,
            },
            None,
        ));
    }

    let cont_refs: Vec<&[u8]> = fragments.iter().skip(1).map(|f| f.as_slice()).collect();
    let parsed = match decode_trailers(decoder, &fragments[0], &cont_refs) {
        Ok(v) => v,
        Err(e) => {
            return Err(Box::new((
                e,
                AssemblerState::CollectingTrailerBlock {
                    request,
                    body,
                    fragments,
                },
            )))
        }
    };

    request.body = body;
    request.trailers = parsed;
    Ok((
        AssemblerState::Complete,
        Some(StreamEvent::RequestComplete(request)),
    ))
}

fn decode_trailers(
    decoder: &mut fingerprint_proxy_hpack::Decoder,
    first_fragment: &[u8],
    continuation_fragments: &[&[u8]],
) -> FpResult<std::collections::BTreeMap<String, String>> {
    let fields = crate::decode_header_block(
        decoder,
        crate::HeaderBlockInput {
            first_fragment,
            continuation_fragments,
        },
    )?;

    let mut trailers = std::collections::BTreeMap::new();
    for field in fields {
        if field.name.starts_with(':') {
            return Err(FpError::invalid_protocol_data(
                "HTTP/2 trailers must not contain pseudo-headers",
            ));
        }
        if is_connection_specific_header(&field.name) {
            return Err(FpError::invalid_protocol_data(
                "HTTP/2 connection-specific header is not allowed",
            ));
        }
        trailers.insert(field.name, field.value);
    }
    Ok(trailers)
}

fn is_connection_specific_header(name: &str) -> bool {
    matches!(
        name,
        "connection" | "proxy-connection" | "keep-alive" | "transfer-encoding" | "upgrade"
    )
}
