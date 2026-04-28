use fingerprint_proxy_core::error::FpError;
use fingerprint_proxy_core::request::HttpRequest;
use fingerprint_proxy_http1::request::{parse_http1_request, Http1ParseError, ParseOptions};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssemblerInput<'a> {
    Bytes(&'a [u8]),
    ConnectionEof,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssemblerEvent {
    NeedMoreData,
    RequestReady(HttpRequest),
    ClientError(ClientRequestError),
    Error(FpError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientRequestErrorStatus {
    BadRequest,
    PayloadTooLarge,
    UriTooLong,
    RequestHeadersTooLarge,
}

impl ClientRequestErrorStatus {
    pub fn status_code(self) -> u16 {
        match self {
            ClientRequestErrorStatus::BadRequest => 400,
            ClientRequestErrorStatus::PayloadTooLarge => 413,
            ClientRequestErrorStatus::UriTooLong => 414,
            ClientRequestErrorStatus::RequestHeadersTooLarge => 431,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientRequestError {
    pub status: ClientRequestErrorStatus,
    pub message: String,
}

impl ClientRequestError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: ClientRequestErrorStatus::BadRequest,
            message: message.into(),
        }
    }

    fn payload_too_large(message: impl Into<String>) -> Self {
        Self {
            status: ClientRequestErrorStatus::PayloadTooLarge,
            message: message.into(),
        }
    }

    fn request_headers_too_large(message: impl Into<String>) -> Self {
        Self {
            status: ClientRequestErrorStatus::RequestHeadersTooLarge,
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_header_bytes: usize,
    pub max_body_bytes: usize,
    pub max_requests_per_connection: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_header_bytes: 64 * 1024,
            max_body_bytes: 1024 * 1024,
            max_requests_per_connection: 128,
        }
    }
}

#[derive(Debug, Clone)]
enum ChunkedState {
    SizeLine,
    Data { remaining: usize },
    DataCrlf,
    Trailers,
}

#[derive(Debug, Clone)]
enum AssemblerState {
    ReadingHeaders,
    ReadingContentLength {
        request: HttpRequest,
        remaining: usize,
        body: Vec<u8>,
    },
    ReadingChunked {
        request: HttpRequest,
        state: ChunkedState,
        body: Vec<u8>,
    },
    ReadingUntilEof {
        request: HttpRequest,
        body: Vec<u8>,
    },
    Closed,
}

#[derive(Debug, Clone)]
pub struct Http1MessageAssembler {
    buffer: Vec<u8>,
    state: AssemblerState,
    saw_eof: bool,
    requests_emitted: usize,
}

impl Default for Http1MessageAssembler {
    fn default() -> Self {
        Self::new()
    }
}

impl Http1MessageAssembler {
    pub fn new() -> Self {
        Self {
            buffer: Vec::new(),
            state: AssemblerState::ReadingHeaders,
            saw_eof: false,
            requests_emitted: 0,
        }
    }

    pub fn push(&mut self, input: AssemblerInput<'_>, limits: Limits) -> Vec<AssemblerEvent> {
        let mut events = Vec::new();

        match input {
            AssemblerInput::Bytes(bytes) => {
                if matches!(self.state, AssemblerState::Closed) {
                    events.push(AssemblerEvent::ClientError(
                        ClientRequestError::bad_request("HTTP/1 connection is closed"),
                    ));
                    return events;
                }
                self.buffer.extend_from_slice(bytes);
            }
            AssemblerInput::ConnectionEof => {
                self.saw_eof = true;
            }
        }

        loop {
            let prior = std::mem::replace(&mut self.state, AssemblerState::Closed);
            match prior {
                AssemblerState::ReadingHeaders => match step_reading_headers(
                    &mut self.buffer,
                    self.saw_eof,
                    self.requests_emitted,
                    limits,
                ) {
                    Ok(ReadingStep::RequestReady(req)) => {
                        self.state = AssemblerState::ReadingHeaders;
                        self.requests_emitted += 1;
                        events.push(AssemblerEvent::RequestReady(req));
                        continue;
                    }
                    Ok(ReadingStep::NeedMore) => {
                        self.state = AssemblerState::ReadingHeaders;
                        events.push(AssemblerEvent::NeedMoreData);
                        break;
                    }
                    Ok(ReadingStep::Transition(next)) => {
                        self.state = next;
                        continue;
                    }
                    Err(e) => {
                        self.state = AssemblerState::Closed;
                        events.push(AssemblerEvent::ClientError(e));
                        break;
                    }
                },
                AssemblerState::ReadingContentLength {
                    request,
                    remaining,
                    body,
                } => match step_reading_content_length(
                    &mut self.buffer,
                    self.saw_eof,
                    limits,
                    request,
                    remaining,
                    body,
                ) {
                    Ok(BodyStep::RequestReady(req)) => {
                        self.state = AssemblerState::ReadingHeaders;
                        self.requests_emitted += 1;
                        events.push(AssemblerEvent::RequestReady(req));
                        continue;
                    }
                    Ok(BodyStep::NeedMore(next)) => {
                        self.state = next;
                        events.push(AssemblerEvent::NeedMoreData);
                        break;
                    }
                    Err(e) => {
                        self.state = AssemblerState::Closed;
                        events.push(AssemblerEvent::ClientError(e));
                        break;
                    }
                },
                AssemblerState::ReadingChunked {
                    request,
                    state,
                    body,
                } => match step_reading_chunked(
                    &mut self.buffer,
                    self.saw_eof,
                    limits,
                    request,
                    state,
                    body,
                ) {
                    Ok(BodyStep::RequestReady(req)) => {
                        self.state = AssemblerState::ReadingHeaders;
                        self.requests_emitted += 1;
                        events.push(AssemblerEvent::RequestReady(req));
                        continue;
                    }
                    Ok(BodyStep::NeedMore(next)) => {
                        self.state = next;
                        events.push(AssemblerEvent::NeedMoreData);
                        break;
                    }
                    Err(e) => {
                        self.state = AssemblerState::Closed;
                        events.push(AssemblerEvent::ClientError(e));
                        break;
                    }
                },
                AssemblerState::ReadingUntilEof { request, body } => {
                    match step_reading_until_eof(
                        &mut self.buffer,
                        self.saw_eof,
                        limits,
                        request,
                        body,
                    ) {
                        Ok(UntilEofStep::RequestReady(req)) => {
                            self.state = AssemblerState::Closed;
                            self.requests_emitted += 1;
                            events.push(AssemblerEvent::RequestReady(req));
                            break;
                        }
                        Ok(UntilEofStep::NeedMore(next)) => {
                            self.state = next;
                            events.push(AssemblerEvent::NeedMoreData);
                            break;
                        }
                        Err(e) => {
                            self.state = AssemblerState::Closed;
                            events.push(AssemblerEvent::ClientError(e));
                            break;
                        }
                    }
                }
                AssemblerState::Closed => {
                    self.state = AssemblerState::Closed;
                    events.push(AssemblerEvent::NeedMoreData);
                    break;
                }
            }
        }

        events
    }

    pub fn take_buffer(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.buffer)
    }
}

enum ReadingStep {
    NeedMore,
    RequestReady(HttpRequest),
    Transition(AssemblerState),
}

enum BodyStep {
    NeedMore(AssemblerState),
    RequestReady(HttpRequest),
}

enum UntilEofStep {
    NeedMore(AssemblerState),
    RequestReady(HttpRequest),
}

type ClientRequestResult<T> = Result<T, ClientRequestError>;

fn step_reading_headers(
    buffer: &mut Vec<u8>,
    saw_eof: bool,
    requests_emitted: usize,
    limits: Limits,
) -> ClientRequestResult<ReadingStep> {
    if requests_emitted >= limits.max_requests_per_connection {
        return Err(ClientRequestError::bad_request(
            "HTTP/1 max_requests_per_connection exceeded",
        ));
    }

    if buffer.len() > limits.max_header_bytes && find_headers_end(buffer).is_none() {
        return Err(ClientRequestError::request_headers_too_large(
            "HTTP/1 header bytes exceed max_header_bytes",
        ));
    }

    if contains_invalid_header_line_endings(buffer) {
        return Err(ClientRequestError::bad_request(
            "HTTP/1 invalid line endings (CRLF required)",
        ));
    }

    let Some(header_end) = find_headers_end(buffer) else {
        if saw_eof {
            return Err(ClientRequestError::bad_request(
                "HTTP/1 unexpected EOF before headers complete",
            ));
        }
        return Ok(ReadingStep::NeedMore);
    };

    let header_block_len = header_end + 4;
    if header_block_len > limits.max_header_bytes {
        return Err(ClientRequestError::request_headers_too_large(
            "HTTP/1 header bytes exceed max_header_bytes",
        ));
    }

    let header_bytes: Vec<u8> = buffer[..header_block_len].to_vec();
    buffer.drain(..header_block_len);

    let mut req = parse_http1_request(
        &header_bytes,
        ParseOptions {
            max_header_bytes: Some(limits.max_header_bytes),
        },
    )
    .map_err(map_http1_parse_error)?;

    let transfer_encoding = get_header_value_ci(&req.headers, "transfer-encoding");
    let content_length = get_header_value_ci(&req.headers, "content-length");

    let is_chunked = match transfer_encoding {
        None => false,
        Some(v) => is_transfer_encoding_chunked(v)?,
    };

    if is_chunked && content_length.is_some() {
        return Err(ClientRequestError::bad_request(
            "HTTP/1 request must not include both transfer-encoding and content-length",
        ));
    }

    if is_chunked {
        return Ok(ReadingStep::Transition(AssemblerState::ReadingChunked {
            request: req,
            state: ChunkedState::SizeLine,
            body: Vec::new(),
        }));
    }

    let content_length = match content_length {
        None => None,
        Some(v) => Some(parse_content_length(v)?),
    };

    if let Some(len) = content_length {
        if len > limits.max_body_bytes {
            return Err(ClientRequestError::payload_too_large(
                "HTTP/1 content-length exceeds max_body_bytes",
            ));
        }
        if len == 0 {
            req.body = Vec::new();
            return Ok(ReadingStep::RequestReady(req));
        }
        return Ok(ReadingStep::Transition(
            AssemblerState::ReadingContentLength {
                request: req,
                remaining: len,
                body: Vec::new(),
            },
        ));
    }

    if method_allows_close_delimited_body(req.method.as_str()) {
        return Ok(ReadingStep::Transition(AssemblerState::ReadingUntilEof {
            request: req,
            body: Vec::new(),
        }));
    }

    req.body = Vec::new();
    Ok(ReadingStep::RequestReady(req))
}

fn step_reading_content_length(
    buffer: &mut Vec<u8>,
    saw_eof: bool,
    limits: Limits,
    mut request: HttpRequest,
    mut remaining: usize,
    mut body: Vec<u8>,
) -> ClientRequestResult<BodyStep> {
    if buffer.is_empty() {
        if saw_eof {
            return Err(ClientRequestError::bad_request(
                "HTTP/1 unexpected EOF before content-length body complete",
            ));
        }
        return Ok(BodyStep::NeedMore(AssemblerState::ReadingContentLength {
            request,
            remaining,
            body,
        }));
    }

    let take = remaining.min(buffer.len());
    if body.len() + take > limits.max_body_bytes {
        return Err(ClientRequestError::payload_too_large(
            "HTTP/1 body exceeds max_body_bytes",
        ));
    }
    body.extend_from_slice(&buffer[..take]);
    buffer.drain(..take);
    remaining -= take;

    if remaining > 0 {
        if saw_eof {
            return Err(ClientRequestError::bad_request(
                "HTTP/1 unexpected EOF before content-length body complete",
            ));
        }
        return Ok(BodyStep::NeedMore(AssemblerState::ReadingContentLength {
            request,
            remaining,
            body,
        }));
    }

    request.body = body;
    Ok(BodyStep::RequestReady(request))
}

fn step_reading_chunked(
    buffer: &mut Vec<u8>,
    saw_eof: bool,
    limits: Limits,
    mut request: HttpRequest,
    mut state: ChunkedState,
    mut body: Vec<u8>,
) -> ClientRequestResult<BodyStep> {
    loop {
        match state {
            ChunkedState::SizeLine => {
                if contains_invalid_header_line_endings(buffer) {
                    return Err(ClientRequestError::bad_request(
                        "HTTP/1 invalid line endings (CRLF required)",
                    ));
                }
                let Some(line_end) = find_crlf(buffer) else {
                    if saw_eof {
                        return Err(ClientRequestError::bad_request(
                            "HTTP/1 unexpected EOF in chunk size line",
                        ));
                    }
                    return Ok(BodyStep::NeedMore(AssemblerState::ReadingChunked {
                        request,
                        state,
                        body,
                    }));
                };
                let line = &buffer[..line_end];
                let size = parse_chunk_size_line(line)?;
                buffer.drain(..line_end + 2);

                if size == 0 {
                    state = ChunkedState::Trailers;
                    continue;
                }

                if body.len() + size > limits.max_body_bytes {
                    return Err(ClientRequestError::payload_too_large(
                        "HTTP/1 body exceeds max_body_bytes",
                    ));
                }

                state = ChunkedState::Data { remaining: size };
            }
            ChunkedState::Data { remaining } => {
                if buffer.len() < remaining {
                    if saw_eof {
                        return Err(ClientRequestError::bad_request(
                            "HTTP/1 unexpected EOF in chunk data",
                        ));
                    }
                    return Ok(BodyStep::NeedMore(AssemblerState::ReadingChunked {
                        request,
                        state: ChunkedState::Data { remaining },
                        body,
                    }));
                }
                body.extend_from_slice(&buffer[..remaining]);
                buffer.drain(..remaining);
                state = ChunkedState::DataCrlf;
            }
            ChunkedState::DataCrlf => {
                if buffer.len() < 2 {
                    if saw_eof {
                        return Err(ClientRequestError::bad_request(
                            "HTTP/1 unexpected EOF after chunk data",
                        ));
                    }
                    return Ok(BodyStep::NeedMore(AssemblerState::ReadingChunked {
                        request,
                        state,
                        body,
                    }));
                }
                if buffer[0] != b'\r' || buffer[1] != b'\n' {
                    return Err(ClientRequestError::bad_request(
                        "HTTP/1 invalid chunk: missing CRLF after data",
                    ));
                }
                buffer.drain(..2);
                state = ChunkedState::SizeLine;
            }
            ChunkedState::Trailers => {
                if contains_invalid_header_line_endings(buffer) {
                    return Err(ClientRequestError::bad_request(
                        "HTTP/1 invalid line endings (CRLF required)",
                    ));
                }
                let Some(end) = find_headers_end(buffer) else {
                    if saw_eof {
                        return Err(ClientRequestError::bad_request(
                            "HTTP/1 unexpected EOF in chunked trailers",
                        ));
                    }
                    return Ok(BodyStep::NeedMore(AssemblerState::ReadingChunked {
                        request,
                        state,
                        body,
                    }));
                };
                let trailer_len = end + 4;
                let trailer_bytes: Vec<u8> = buffer[..trailer_len].to_vec();
                buffer.drain(..trailer_len);

                request.trailers = parse_http1_trailers(&trailer_bytes, limits.max_header_bytes)?;
                request.body = body;
                return Ok(BodyStep::RequestReady(request));
            }
        }
    }
}

fn step_reading_until_eof(
    buffer: &mut Vec<u8>,
    saw_eof: bool,
    limits: Limits,
    mut request: HttpRequest,
    mut body: Vec<u8>,
) -> ClientRequestResult<UntilEofStep> {
    if !buffer.is_empty() {
        let remaining = limits.max_body_bytes.saturating_sub(body.len());
        if buffer.len() > remaining {
            return Err(ClientRequestError::payload_too_large(
                "HTTP/1 close-delimited body exceeds max_body_bytes",
            ));
        }
        body.extend_from_slice(buffer);
        buffer.clear();
    }

    if saw_eof {
        request.body = body;
        return Ok(UntilEofStep::RequestReady(request));
    }

    Ok(UntilEofStep::NeedMore(AssemblerState::ReadingUntilEof {
        request,
        body,
    }))
}

fn find_headers_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}

fn contains_invalid_header_line_endings(buf: &[u8]) -> bool {
    buf.iter().enumerate().any(|(i, &b)| {
        if b != b'\n' {
            return false;
        }
        i == 0 || buf[i - 1] != b'\r'
    })
}

fn get_header_value_ci<'a>(
    headers: &'a std::collections::BTreeMap<String, String>,
    name: &str,
) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn parse_content_length(value: &str) -> ClientRequestResult<usize> {
    let v = value.trim();
    if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ClientRequestError::bad_request(
            "HTTP/1 invalid content-length",
        ));
    }
    v.parse::<usize>()
        .map_err(|_| ClientRequestError::bad_request("HTTP/1 invalid content-length"))
}

fn is_transfer_encoding_chunked(value: &str) -> ClientRequestResult<bool> {
    let tokens: Vec<&str> = value
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();
    if tokens.is_empty() {
        return Err(ClientRequestError::bad_request(
            "HTTP/1 invalid transfer-encoding",
        ));
    }
    let lower: Vec<String> = tokens.iter().map(|t| t.to_ascii_lowercase()).collect();
    if lower.iter().any(|t| t == "chunked") {
        return Ok(true);
    }
    Err(ClientRequestError::bad_request(
        "HTTP/1 unsupported transfer-encoding",
    ))
}

fn parse_chunk_size_line(line: &[u8]) -> ClientRequestResult<usize> {
    let s = std::str::from_utf8(line)
        .map_err(|_| ClientRequestError::bad_request("HTTP/1 invalid chunk size line"))?;
    let (size_part, _) = s.split_once(';').unwrap_or((s, ""));
    let size_part = size_part.trim();
    if size_part.is_empty() {
        return Err(ClientRequestError::bad_request("HTTP/1 invalid chunk size"));
    }
    usize::from_str_radix(size_part, 16)
        .map_err(|_| ClientRequestError::bad_request("HTTP/1 invalid chunk size"))
}

fn method_allows_close_delimited_body(method: &str) -> bool {
    matches!(
        method,
        "POST" | "PUT" | "PATCH" | "DELETE" | "post" | "put" | "patch" | "delete"
    )
}

fn parse_http1_trailers(
    trailer_section: &[u8],
    max_header_bytes: usize,
) -> ClientRequestResult<std::collections::BTreeMap<String, String>> {
    let mut synthetic = Vec::with_capacity(b"GET / HTTP/1.1\r\n".len() + trailer_section.len());
    synthetic.extend_from_slice(b"GET / HTTP/1.1\r\n");
    synthetic.extend_from_slice(trailer_section);

    let parsed = parse_http1_request(
        &synthetic,
        ParseOptions {
            max_header_bytes: Some(max_header_bytes),
        },
    )
    .map_err(map_http1_trailer_parse_error)?;

    Ok(parsed.headers)
}

fn map_http1_parse_error(error: Http1ParseError) -> ClientRequestError {
    match error {
        Http1ParseError::HeaderTooLarge { .. } => {
            ClientRequestError::request_headers_too_large(format!("HTTP/1 parse error: {error:?}"))
        }
        _ => ClientRequestError::bad_request(format!("HTTP/1 parse error: {error:?}")),
    }
}

fn map_http1_trailer_parse_error(error: Http1ParseError) -> ClientRequestError {
    match error {
        Http1ParseError::HeaderTooLarge { .. } => ClientRequestError::request_headers_too_large(
            format!("HTTP/1 trailer parse error: {error:?}"),
        ),
        _ => ClientRequestError::bad_request(format!("HTTP/1 trailer parse error: {error:?}")),
    }
}
