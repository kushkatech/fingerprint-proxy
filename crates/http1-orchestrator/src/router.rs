use fingerprint_proxy_core::error::{FpError, FpResult};
use fingerprint_proxy_core::http_date::current_http_date;
use fingerprint_proxy_core::request::{HttpRequest, HttpResponse, RequestContext};
use fingerprint_proxy_pipeline::Pipeline;
use fingerprint_proxy_prepipeline::{
    run_prepared_pipeline, OrchestrationOutcome, PrePipelineInput,
};
use std::future::Future;
use std::pin::Pin;

use crate::message_assembler::{
    AssemblerEvent, AssemblerInput, ClientRequestError, Http1MessageAssembler, Limits,
};

pub trait Http1RouterDeps: Send + Sync {
    fn pipeline(&self) -> &Pipeline;
    fn build_prepipeline_input(&self, request: HttpRequest) -> FpResult<PrePipelineInput>;
    fn handle_continued<'a>(
        &'a self,
        ctx: RequestContext,
    ) -> Pin<Box<dyn Future<Output = FpResult<HttpResponse>> + Send + 'a>>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingWebSocketUpgrade {
    pub ctx: RequestContext,
    pub initial_client_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Http1ProcessOutput {
    Responses(Vec<Vec<u8>>),
    CloseAfterResponses(Vec<Vec<u8>>),
    WebSocketUpgrade(Box<PendingWebSocketUpgrade>),
}

#[derive(Debug, Clone)]
pub struct Http1ConnectionRouter {
    assembler: Http1MessageAssembler,
    limits: Limits,
}

impl Default for Http1ConnectionRouter {
    fn default() -> Self {
        Self::new()
    }
}

impl Http1ConnectionRouter {
    pub fn new() -> Self {
        Self {
            assembler: Http1MessageAssembler::new(),
            limits: Limits::default(),
        }
    }

    pub fn with_limits(limits: Limits) -> Self {
        Self {
            assembler: Http1MessageAssembler::new(),
            limits,
        }
    }

    pub async fn process(
        &mut self,
        input: AssemblerInput<'_>,
        deps: &dyn Http1RouterDeps,
    ) -> FpResult<Http1ProcessOutput> {
        let mut out = Vec::new();
        for ev in self.assembler.push(input, self.limits) {
            match ev {
                AssemblerEvent::NeedMoreData => {}
                AssemblerEvent::RequestReady(request) => {
                    let pre = deps.build_prepipeline_input(request)?;
                    match run_prepared_pipeline(&pre, deps.pipeline()) {
                        Ok(OrchestrationOutcome::Stopped { response, .. }) => {
                            out.push(serialize_http1_router_response(&response)?);
                        }
                        Ok(OrchestrationOutcome::Continued { ctx, .. }) => {
                            if fingerprint_proxy_http1::websocket_request_requires_takeover(
                                &ctx.request,
                            ) {
                                return Ok(Http1ProcessOutput::WebSocketUpgrade(Box::new(
                                    PendingWebSocketUpgrade {
                                        ctx: *ctx,
                                        initial_client_bytes: self.assembler.take_buffer(),
                                    },
                                )));
                            }
                            let response = deps.handle_continued(*ctx).await?;
                            out.push(serialize_http1_router_response(&response)?);
                        }
                        Err(e) => return Err(e),
                    }
                }
                AssemblerEvent::ClientError(e) => {
                    out.push(serialize_http1_client_error_response(&e)?);
                    return Ok(Http1ProcessOutput::CloseAfterResponses(out));
                }
                AssemblerEvent::Error(e) => return Err(e),
            }
        }

        Ok(Http1ProcessOutput::Responses(out))
    }

    pub async fn process_bytes(
        &mut self,
        incoming: &[u8],
        deps: &dyn Http1RouterDeps,
    ) -> FpResult<Http1ProcessOutput> {
        self.process(AssemblerInput::Bytes(incoming), deps).await
    }
}

fn serialize_http1_router_response(
    response: &fingerprint_proxy_core::request::HttpResponse,
) -> FpResult<Vec<u8>> {
    if response.trailers.is_empty() {
        let mut bytes =
            fingerprint_proxy_http1::serialize_http1_response(response).map_err(|e| {
                FpError::invalid_protocol_data(format!("HTTP/1 serialize error: {e:?}"))
            })?;
        bytes.extend_from_slice(&response.body);
        return Ok(bytes);
    }

    validate_http1_trailer_map(&response.trailers)?;

    let mut head = response.clone();
    head.headers
        .insert("Transfer-Encoding".to_string(), "chunked".to_string());
    head.headers.remove("Content-Length");

    let mut out = fingerprint_proxy_http1::serialize_http1_response(&head)
        .map_err(|e| FpError::invalid_protocol_data(format!("HTTP/1 serialize error: {e:?}")))?;

    if !response.body.is_empty() {
        out.extend_from_slice(format!("{:x}\r\n", response.body.len()).as_bytes());
        out.extend_from_slice(&response.body);
        out.extend_from_slice(b"\r\n");
    }

    out.extend_from_slice(b"0\r\n");
    for (name, value) in &response.trailers {
        write_http1_trailer_line(&mut out, name, value)?;
    }
    out.extend_from_slice(b"\r\n");

    Ok(out)
}

fn serialize_http1_client_error_response(error: &ClientRequestError) -> FpResult<Vec<u8>> {
    let mut response = HttpResponse {
        version: "HTTP/1.1".to_string(),
        status: Some(error.status.status_code()),
        ..HttpResponse::default()
    };
    response
        .headers
        .insert("Content-Length".to_string(), "0".to_string());
    response
        .headers
        .insert("Date".to_string(), current_http_date());
    response
        .headers
        .insert("Connection".to_string(), "close".to_string());
    serialize_http1_router_response(&response)
}

fn validate_http1_trailer_map(
    trailers: &std::collections::BTreeMap<String, String>,
) -> FpResult<()> {
    for (name, value) in trailers {
        validate_http1_trailer_name(name)?;
        validate_http1_trailer_value(value)?;
        if is_connection_specific_header(name) {
            return Err(FpError::invalid_protocol_data(
                "HTTP/1 connection-specific trailer header is not allowed",
            ));
        }
    }
    Ok(())
}

fn write_http1_trailer_line(out: &mut Vec<u8>, name: &str, value: &str) -> FpResult<()> {
    validate_http1_trailer_name(name)?;
    validate_http1_trailer_value(value)?;
    if is_connection_specific_header(name) {
        return Err(FpError::invalid_protocol_data(
            "HTTP/1 connection-specific trailer header is not allowed",
        ));
    }

    out.extend_from_slice(name.trim().as_bytes());
    out.extend_from_slice(b": ");
    out.extend_from_slice(value.as_bytes());
    out.extend_from_slice(b"\r\n");
    Ok(())
}

fn validate_http1_trailer_name(name: &str) -> FpResult<()> {
    let name = name.trim();
    if name.is_empty() {
        return Err(FpError::invalid_protocol_data(
            "HTTP/1 trailer header name must be non-empty",
        ));
    }
    if !is_http_token(name) || name.bytes().any(|b| b == b' ' || b == b'\t') {
        return Err(FpError::invalid_protocol_data(
            "HTTP/1 trailer header name is invalid",
        ));
    }
    Ok(())
}

fn validate_http1_trailer_value(value: &str) -> FpResult<()> {
    if value.as_bytes().iter().any(|b| *b == b'\r' || *b == b'\n') {
        return Err(FpError::invalid_protocol_data(
            "HTTP/1 trailer header value must not contain CR or LF",
        ));
    }
    Ok(())
}

fn is_http_token(s: &str) -> bool {
    s.bytes().all(is_http_token_char)
}

fn is_http_token_char(b: u8) -> bool {
    matches!(
        b,
        b'0'..=b'9'
            | b'a'..=b'z'
            | b'A'..=b'Z'
            | b'!'
            | b'#'
            | b'$'
            | b'%'
            | b'&'
            | b'\''
            | b'*'
            | b'+'
            | b'-'
            | b'.'
            | b'^'
            | b'_'
            | b'`'
            | b'|'
            | b'~'
    )
}

fn is_connection_specific_header(name: &str) -> bool {
    matches!(
        name.trim().to_ascii_lowercase().as_str(),
        "connection" | "proxy-connection" | "keep-alive" | "transfer-encoding" | "upgrade"
    )
}
