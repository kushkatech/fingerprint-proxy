use fingerprint_proxy_core::error::FpResult;
use fingerprint_proxy_core::request::{HttpRequest, HttpResponse, RequestContext};
use fingerprint_proxy_http2::frames::Frame;
use fingerprint_proxy_http2::{Http2RequestStreamAssembler, StreamEvent, StreamId};
use fingerprint_proxy_pipeline::Pipeline;
use fingerprint_proxy_prepipeline::{
    run_prepared_pipeline, OrchestrationOutcome, PrePipelineInput,
};
use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;

pub trait RouterDeps: Send {
    fn hpack_decoder(&mut self) -> &mut fingerprint_proxy_hpack::Decoder;
    fn hpack_encoder(&mut self) -> &mut fingerprint_proxy_hpack::Encoder;
    fn pipeline(&self) -> &Pipeline;
    fn build_prepipeline_input(&self, request: HttpRequest) -> FpResult<PrePipelineInput>;
    fn handle_continued<'a>(
        &'a mut self,
        ctx: RequestContext,
    ) -> Pin<Box<dyn Future<Output = FpResult<HttpResponse>> + Send + 'a>>;
}

#[derive(Debug, Default)]
pub struct Http2ConnectionRouter {
    streams: BTreeMap<StreamId, Http2RequestStreamAssembler>,
}

impl Http2ConnectionRouter {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn process_frame(
        &mut self,
        frame: Frame,
        deps: &mut dyn RouterDeps,
    ) -> FpResult<Vec<Frame>> {
        let stream_id = frame.header.stream_id;
        if stream_id.is_connection() {
            return Ok(Vec::new());
        }

        let ev = {
            let assembler = self
                .streams
                .entry(stream_id)
                .or_insert_with(|| Http2RequestStreamAssembler::new(stream_id));
            assembler.push_frame(deps.hpack_decoder(), frame)?
        };

        match ev {
            None | Some(StreamEvent::RequestHeadersReady(_)) => Ok(Vec::new()),
            Some(StreamEvent::RequestComplete(request)) => {
                self.streams.remove(&stream_id);

                let pre = deps.build_prepipeline_input(request)?;
                match run_prepared_pipeline(&pre, deps.pipeline()) {
                    Ok(OrchestrationOutcome::Stopped { response, .. }) => {
                        self.encode_response(stream_id, &response, deps)
                    }
                    Ok(OrchestrationOutcome::Continued { ctx, .. }) => {
                        let response = deps.handle_continued(*ctx).await?;
                        self.encode_response(stream_id, &response, deps)
                    }
                    Err(e) => Err(e),
                }
            }
        }
    }

    fn encode_response(
        &self,
        stream_id: StreamId,
        response: &HttpResponse,
        deps: &mut dyn RouterDeps,
    ) -> FpResult<Vec<Frame>> {
        fingerprint_proxy_http2::encode_http2_response_frames(
            deps.hpack_encoder(),
            stream_id,
            response,
        )
    }
}
