use fingerprint_proxy_core::error::FpResult;
use fingerprint_proxy_core::request::{HttpRequest, HttpResponse, RequestContext};
use fingerprint_proxy_http2::frames::Frame;
use fingerprint_proxy_http2::{Http2RequestStreamAssembler, StreamEvent, StreamId};
use fingerprint_proxy_pipeline::Pipeline;
use fingerprint_proxy_prepipeline::{
    run_prepared_pipeline, OrchestrationOutcome, PrePipelineInput,
};
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::Pin;

pub enum GrpcStreamingStart {
    NotStreaming,
    Started,
    Responded(Vec<Frame>),
}

pub trait RouterDeps: Send {
    fn hpack_decoder(&mut self) -> &mut fingerprint_proxy_hpack::Decoder;
    fn hpack_encoder(&mut self) -> &mut fingerprint_proxy_hpack::Encoder;
    fn pipeline(&self) -> &Pipeline;
    fn build_prepipeline_input(&self, request: HttpRequest) -> FpResult<PrePipelineInput>;
    fn spawn_continued(&mut self, stream_id: StreamId, ctx: RequestContext) -> FpResult<()>;
    fn try_start_grpc_streaming<'a>(
        &'a mut self,
        stream_id: StreamId,
        request: HttpRequest,
    ) -> Pin<Box<dyn Future<Output = FpResult<GrpcStreamingStart>> + Send + 'a>> {
        let _ = (stream_id, request);
        Box::pin(async { Ok(GrpcStreamingStart::NotStreaming) })
    }
    fn submit_grpc_stream_data<'a>(
        &'a mut self,
        stream_id: StreamId,
        bytes: Vec<u8>,
        end_stream: bool,
    ) -> Pin<Box<dyn Future<Output = FpResult<()>> + Send + 'a>> {
        let _ = (stream_id, bytes, end_stream);
        Box::pin(async {
            Err(
                fingerprint_proxy_core::error::FpError::invalid_protocol_data(
                    "gRPC HTTP/2 streaming request is not active",
                ),
            )
        })
    }
    fn submit_grpc_stream_trailers<'a>(
        &'a mut self,
        stream_id: StreamId,
        trailers: std::collections::BTreeMap<String, String>,
    ) -> Pin<Box<dyn Future<Output = FpResult<()>> + Send + 'a>> {
        let _ = (stream_id, trailers);
        Box::pin(async {
            Err(
                fingerprint_proxy_core::error::FpError::invalid_protocol_data(
                    "gRPC HTTP/2 streaming request is not active",
                ),
            )
        })
    }
}

#[derive(Debug, Default)]
pub struct Http2ConnectionRouter {
    streams: BTreeMap<StreamId, Http2RequestStreamAssembler>,
    grpc_streaming: BTreeSet<StreamId>,
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
            None => Ok(Vec::new()),
            Some(StreamEvent::RequestHeadersReady(request)) => {
                match deps.try_start_grpc_streaming(stream_id, request).await? {
                    GrpcStreamingStart::NotStreaming => Ok(Vec::new()),
                    GrpcStreamingStart::Started => {
                        self.grpc_streaming.insert(stream_id);
                        Ok(Vec::new())
                    }
                    GrpcStreamingStart::Responded(frames) => {
                        self.streams.remove(&stream_id);
                        Ok(frames)
                    }
                }
            }
            Some(StreamEvent::RequestBodyData {
                request_complete: None,
                bytes,
                end_stream,
                ..
            }) if self.grpc_streaming.contains(&stream_id) => {
                deps.submit_grpc_stream_data(stream_id, bytes, end_stream)
                    .await?;
                if end_stream {
                    self.streams.remove(&stream_id);
                    self.grpc_streaming.remove(&stream_id);
                }
                Ok(Vec::new())
            }
            Some(StreamEvent::RequestBodyData {
                request_complete: None,
                ..
            }) => Ok(Vec::new()),
            Some(StreamEvent::RequestBodyData {
                request_complete: Some(request),
                bytes,
                end_stream,
                ..
            }) if self.grpc_streaming.contains(&stream_id) => {
                deps.submit_grpc_stream_data(stream_id, bytes, end_stream)
                    .await?;
                self.streams.remove(&stream_id);
                self.grpc_streaming.remove(&stream_id);
                let _ = request;
                Ok(Vec::new())
            }
            Some(StreamEvent::RequestTrailersReady {
                trailers,
                request_complete: request,
            }) if self.grpc_streaming.contains(&stream_id) => {
                deps.submit_grpc_stream_trailers(stream_id, trailers)
                    .await?;
                self.streams.remove(&stream_id);
                self.grpc_streaming.remove(&stream_id);
                let _ = request;
                Ok(Vec::new())
            }
            Some(StreamEvent::RequestBodyData {
                request_complete: Some(request),
                ..
            })
            | Some(StreamEvent::RequestTrailersReady {
                request_complete: request,
                ..
            }) => {
                self.streams.remove(&stream_id);
                self.grpc_streaming.remove(&stream_id);

                let pre = deps.build_prepipeline_input(request)?;
                match run_prepared_pipeline(&pre, deps.pipeline()) {
                    Ok(OrchestrationOutcome::Stopped { response, .. }) => {
                        self.encode_response(stream_id, &response, deps)
                    }
                    Ok(OrchestrationOutcome::Continued { ctx, .. }) => {
                        deps.spawn_continued(stream_id, *ctx)?;
                        Ok(Vec::new())
                    }
                    Err(e) => Err(e),
                }
            }
            Some(StreamEvent::RequestComplete(request)) => {
                self.streams.remove(&stream_id);

                let pre = deps.build_prepipeline_input(request)?;
                match run_prepared_pipeline(&pre, deps.pipeline()) {
                    Ok(OrchestrationOutcome::Stopped { response, .. }) => {
                        self.encode_response(stream_id, &response, deps)
                    }
                    Ok(OrchestrationOutcome::Continued { ctx, .. }) => {
                        deps.spawn_continued(stream_id, *ctx)?;
                        Ok(Vec::new())
                    }
                    Err(e) => Err(e),
                }
            }
        }
    }

    pub fn encode_response(
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
