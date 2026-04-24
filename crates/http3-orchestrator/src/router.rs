use fingerprint_proxy_core::error::{FpError, FpResult};
use fingerprint_proxy_core::request::{HttpRequest, HttpResponse};
use fingerprint_proxy_http3::{
    build_request_from_raw_parts, encode_response_frames, validate_request_stream_id, Frame,
    HeaderField, Http3RequestStreamAssembler, StreamEvent,
};
use fingerprint_proxy_pipeline::Pipeline;
use fingerprint_proxy_prepipeline::{
    run_prepared_pipeline, OrchestrationOutcome, PrePipelineInput,
};
use std::collections::BTreeMap;

pub trait RouterDeps {
    fn decode_request_headers(&self, raw_headers: &[u8]) -> FpResult<Vec<HeaderField>>;
    fn encode_response_headers(&self, resp: &HttpResponse) -> FpResult<Vec<u8>>;
    fn encode_response_trailers(
        &self,
        trailers: &std::collections::BTreeMap<String, String>,
    ) -> FpResult<Vec<u8>>;
    fn pipeline(&self) -> &Pipeline;
    fn build_prepipeline_input(&self, request: HttpRequest) -> FpResult<PrePipelineInput>;
}

#[derive(Debug, Default)]
pub struct Http3ConnectionRouter {
    streams: BTreeMap<u64, Http3RequestStreamAssembler>,
}

#[derive(Debug)]
struct CompletedRequest {
    headers: Vec<u8>,
    trailers: Option<Vec<u8>>,
    body: Vec<u8>,
}

impl Http3ConnectionRouter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn process_frame(
        &mut self,
        stream_id: u64,
        frame: Frame,
        _deps: &dyn RouterDeps,
    ) -> FpResult<Vec<Frame>> {
        ensure_request_stream_id(stream_id)?;
        let assembler = self.streams.entry(stream_id).or_default();

        let events = assembler.push_frame(frame)?;
        for ev in events {
            if matches!(ev, StreamEvent::RequestComplete { .. }) {
                return Err(FpError::internal(
                    "HTTP/3 RequestComplete must be triggered by finish_stream()",
                ));
            }
        }
        Ok(Vec::new())
    }

    pub fn finish_stream(&mut self, stream_id: u64, deps: &dyn RouterDeps) -> FpResult<Vec<Frame>> {
        ensure_request_stream_id(stream_id)?;
        let Some(mut assembler) = self.streams.remove(&stream_id) else {
            return Err(FpError::invalid_protocol_data("HTTP/3 unknown stream_id"));
        };

        let events = assembler.finish_stream()?;
        let mut complete: Option<CompletedRequest> = None;
        for ev in events {
            match ev {
                StreamEvent::RequestHeadersReady(_) => {}
                StreamEvent::RequestComplete {
                    headers,
                    trailers,
                    body,
                } => {
                    complete = Some(CompletedRequest {
                        headers,
                        trailers,
                        body,
                    });
                }
            }
        }

        let Some(CompletedRequest {
            headers: raw_headers,
            trailers: raw_trailers,
            body,
        }) = complete
        else {
            return Err(FpError::internal(
                "HTTP/3 finish_stream produced no RequestComplete",
            ));
        };

        let request =
            build_request_from_raw_parts(&raw_headers, raw_trailers.as_deref(), body, |raw| {
                deps.decode_request_headers(raw)
            })?;

        let pre = deps.build_prepipeline_input(request)?;
        match run_prepared_pipeline(&pre, deps.pipeline()) {
            Ok(OrchestrationOutcome::Stopped { response, .. }) => encode_response_frames(
                &response,
                |resp| deps.encode_response_headers(resp),
                |trailers| deps.encode_response_trailers(trailers),
            ),
            Ok(OrchestrationOutcome::Continued { .. }) => Err(FpError::invalid_protocol_data(
                "STUB[T291]: HTTP/3 upstream is not implemented",
            )),
            Err(e) => Err(e),
        }
    }
}

fn ensure_request_stream_id(stream_id: u64) -> FpResult<()> {
    validate_request_stream_id(stream_id)
}
