use fingerprint_proxy_core::connection::{ConnectionContext, TransportProtocol};
use fingerprint_proxy_core::enrichment::ModuleDecision;
use fingerprint_proxy_core::error::FpError;
use fingerprint_proxy_core::fingerprint::{Fingerprint, FingerprintAvailability, FingerprintKind};
use fingerprint_proxy_core::fingerprinting::FingerprintComputationResult;
use fingerprint_proxy_core::identifiers::{ConfigVersion, ConnectionId, RequestId};
use fingerprint_proxy_core::request::{HttpRequest, HttpResponse, RequestContext};
use fingerprint_proxy_hpack::{Decoder, DecoderConfig, Encoder, EncoderConfig};
use fingerprint_proxy_http2::frames::{Frame, FrameHeader, FramePayload, FrameType};
use fingerprint_proxy_http2::{
    decode_header_block, map_headers_to_response, HeaderBlockInput, StreamId,
};
use fingerprint_proxy_http2_orchestrator::{Http2ConnectionRouter, RouterDeps};
use fingerprint_proxy_pipeline::module::{PipelineModule, PipelineModuleResult};
use fingerprint_proxy_pipeline::response::set_response_status;
use fingerprint_proxy_pipeline::Pipeline;
use fingerprint_proxy_prepipeline::PrePipelineInput;
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::SystemTime;

fn make_connection() -> ConnectionContext {
    let client = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 12345);
    let dest = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)), 443);
    ConnectionContext::new(
        ConnectionId(1),
        client,
        dest,
        TransportProtocol::Tcp,
        SystemTime::UNIX_EPOCH,
        ConfigVersion::new("cfg-1").expect("test config version"),
    )
}

fn make_fingerprinting_result(computed_at: SystemTime) -> FingerprintComputationResult {
    let ja4t = Fingerprint {
        kind: FingerprintKind::Ja4T,
        availability: FingerprintAvailability::Complete,
        value: Some("ja4t".to_string()),
        computed_at: Some(computed_at),
        failure_reason: None,
    };
    let ja4 = Fingerprint {
        kind: FingerprintKind::Ja4,
        availability: FingerprintAvailability::Unavailable,
        value: None,
        computed_at: Some(computed_at),
        failure_reason: None,
    };
    let ja4one = Fingerprint {
        kind: FingerprintKind::Ja4One,
        availability: FingerprintAvailability::Partial,
        value: Some("ja4one".to_string()),
        computed_at: Some(computed_at),
        failure_reason: None,
    };
    FingerprintComputationResult::from_parts(ja4t, ja4, ja4one, computed_at)
}

fn new_decoder() -> Decoder {
    Decoder::new(DecoderConfig {
        max_dynamic_table_size: 4096,
    })
}

fn new_encoder() -> Encoder {
    Encoder::new(EncoderConfig {
        max_dynamic_table_size: 4096,
        use_huffman: false,
    })
}

fn hex_bytes(s: &str) -> Vec<u8> {
    let cleaned: String = s.split_whitespace().collect();
    assert!(cleaned.len().is_multiple_of(2));
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    for i in (0..cleaned.len()).step_by(2) {
        out.push(u8::from_str_radix(&cleaned[i..i + 2], 16).unwrap());
    }
    out
}

fn headers_only_request_frame(stream_id: StreamId) -> Frame {
    // RFC 7541 Appendix C.3.1 (no Huffman)
    let block = hex_bytes("82 86 84 41 0f 77 77 77 2e 65 78 61 6d 70 6c 65 2e 63 6f 6d");
    Frame {
        header: FrameHeader {
            length: block.len() as u32,
            frame_type: FrameType::Headers,
            flags: 0x5, // END_STREAM | END_HEADERS
            stream_id,
        },
        payload: FramePayload::Headers(block),
    }
}

fn headers_start_frame(stream_id: StreamId, first: Vec<u8>) -> Frame {
    Frame {
        header: FrameHeader {
            length: first.len() as u32,
            frame_type: FrameType::Headers,
            flags: 0x0, // no END_HEADERS, no END_STREAM
            stream_id,
        },
        payload: FramePayload::Headers(first),
    }
}

fn continuation_end_headers_frame(stream_id: StreamId, second: Vec<u8>) -> Frame {
    Frame {
        header: FrameHeader {
            length: second.len() as u32,
            frame_type: FrameType::Continuation,
            flags: 0x5, // END_HEADERS | END_STREAM
            stream_id,
        },
        payload: FramePayload::Continuation(second),
    }
}

fn headers_only_request_frame_split(stream_id: StreamId) -> (Frame, Frame) {
    // RFC 7541 Appendix C.3.1 (no Huffman)
    let block = hex_bytes("82 86 84 41 0f 77 77 77 2e 65 78 61 6d 70 6c 65 2e 63 6f 6d");
    let (first, second) = block.split_at(5);
    (
        headers_start_frame(stream_id, first.to_vec()),
        continuation_end_headers_frame(stream_id, second.to_vec()),
    )
}

struct TerminateModule {
    status: u16,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

impl PipelineModule for TerminateModule {
    fn name(&self) -> &'static str {
        "terminate"
    }

    fn handle(&self, ctx: &mut RequestContext) -> PipelineModuleResult {
        set_response_status(ctx, self.status);
        ctx.response.headers = self.headers.clone();
        ctx.response.body = self.body.clone();
        Ok(ModuleDecision::Terminate)
    }
}

struct ContinueModule;

impl PipelineModule for ContinueModule {
    fn name(&self) -> &'static str {
        "cont"
    }

    fn handle(&self, _ctx: &mut RequestContext) -> PipelineModuleResult {
        Ok(ModuleDecision::Continue)
    }
}

struct ErrorModule;

impl PipelineModule for ErrorModule {
    fn name(&self) -> &'static str {
        "err"
    }

    fn handle(&self, _ctx: &mut RequestContext) -> PipelineModuleResult {
        Err(FpError::internal("boom"))
    }
}

struct TestDeps<'a> {
    decoder: Decoder,
    encoder: Encoder,
    pipeline: &'a Pipeline,
    continued_response: HttpResponse,
}

impl RouterDeps for TestDeps<'_> {
    fn hpack_decoder(&mut self) -> &mut Decoder {
        &mut self.decoder
    }

    fn hpack_encoder(&mut self) -> &mut Encoder {
        &mut self.encoder
    }

    fn pipeline(&self) -> &Pipeline {
        self.pipeline
    }

    fn build_prepipeline_input(
        &self,
        request: HttpRequest,
    ) -> fingerprint_proxy_core::error::FpResult<PrePipelineInput> {
        Ok(PrePipelineInput {
            id: RequestId(1),
            connection: make_connection(),
            request,
            response: HttpResponse::default(),
            virtual_host: None,
            module_config: BTreeMap::new(),
            client_network_rules: Vec::new(),
            fingerprinting_result: make_fingerprinting_result(SystemTime::UNIX_EPOCH),
        })
    }

    fn handle_continued<'a>(
        &'a mut self,
        _ctx: RequestContext,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = fingerprint_proxy_core::error::FpResult<HttpResponse>>
                + Send
                + 'a,
        >,
    > {
        let resp = self.continued_response.clone();
        Box::pin(async move { Ok(resp) })
    }
}

#[tokio::test]
async fn routes_single_stream_request_to_pipeline_and_emits_response_frames() {
    let mut headers = BTreeMap::new();
    headers.insert("content-type".to_string(), "text/plain".to_string());

    let pipeline = Pipeline::new(vec![Box::new(TerminateModule {
        status: 200,
        headers,
        body: Vec::new(),
    })]);

    let mut deps = TestDeps {
        decoder: new_decoder(),
        encoder: new_encoder(),
        pipeline: &pipeline,
        continued_response: HttpResponse::default(),
    };

    let stream_id = StreamId::new(1).unwrap();
    let mut router = Http2ConnectionRouter::new();

    let frames = router
        .process_frame(headers_only_request_frame(stream_id), &mut deps)
        .await
        .expect("process");
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].header.stream_id, stream_id);
    assert_eq!(frames[0].header.frame_type, FrameType::Headers);

    let FramePayload::Headers(block) = &frames[0].payload else {
        panic!("expected HEADERS payload");
    };

    let mut resp_decoder = new_decoder();
    let fields = decode_header_block(
        &mut resp_decoder,
        HeaderBlockInput {
            first_fragment: block,
            continuation_fragments: &[],
        },
    )
    .expect("decode");
    let resp = map_headers_to_response(&fields).expect("map");
    assert_eq!(resp.status, Some(200));
    assert_eq!(
        resp.headers.get("content-type").map(String::as_str),
        Some("text/plain")
    );
}

#[tokio::test]
async fn response_with_body_emits_data_frame() {
    let pipeline = Pipeline::new(vec![Box::new(TerminateModule {
        status: 200,
        headers: BTreeMap::new(),
        body: b"abc".to_vec(),
    })]);

    let mut deps = TestDeps {
        decoder: new_decoder(),
        encoder: new_encoder(),
        pipeline: &pipeline,
        continued_response: HttpResponse::default(),
    };

    let stream_id = StreamId::new(1).unwrap();
    let mut router = Http2ConnectionRouter::new();

    let frames = router
        .process_frame(headers_only_request_frame(stream_id), &mut deps)
        .await
        .expect("process");
    assert_eq!(frames.len(), 2);
    assert_eq!(frames[0].header.frame_type, FrameType::Headers);
    assert_eq!(frames[1].header.frame_type, FrameType::Data);
    let FramePayload::Data(bytes) = &frames[1].payload else {
        panic!("expected DATA payload");
    };
    assert_eq!(bytes, b"abc");
}

#[tokio::test]
async fn pipeline_error_is_propagated() {
    let pipeline = Pipeline::new(vec![Box::new(ErrorModule)]);
    let mut deps = TestDeps {
        decoder: new_decoder(),
        encoder: new_encoder(),
        pipeline: &pipeline,
        continued_response: HttpResponse::default(),
    };

    let stream_id = StreamId::new(1).unwrap();
    let mut router = Http2ConnectionRouter::new();

    let err = router
        .process_frame(headers_only_request_frame(stream_id), &mut deps)
        .await
        .expect_err("must error");
    assert_eq!(err.message, "boom");
}

#[tokio::test]
async fn continued_pipeline_is_forwarded_via_deps_callback() {
    let pipeline = Pipeline::new(vec![Box::new(ContinueModule)]);
    let mut continued = HttpResponse {
        version: "HTTP/2".to_string(),
        status: Some(201),
        ..HttpResponse::default()
    };
    continued
        .headers
        .insert("x-from-upstream".to_string(), "1".to_string());
    let mut deps = TestDeps {
        decoder: new_decoder(),
        encoder: new_encoder(),
        pipeline: &pipeline,
        continued_response: continued,
    };

    let stream_id = StreamId::new(1).unwrap();
    let mut router = Http2ConnectionRouter::new();

    let frames = router
        .process_frame(headers_only_request_frame(stream_id), &mut deps)
        .await
        .expect("process");
    assert_eq!(frames.len(), 1);
    let FramePayload::Headers(block) = &frames[0].payload else {
        panic!("expected HEADERS payload");
    };
    let mut resp_decoder = new_decoder();
    let fields = decode_header_block(
        &mut resp_decoder,
        HeaderBlockInput {
            first_fragment: block,
            continuation_fragments: &[],
        },
    )
    .expect("decode");
    let resp = map_headers_to_response(&fields).expect("map");
    assert_eq!(resp.status, Some(201));
    assert_eq!(
        resp.headers.get("x-from-upstream").map(String::as_str),
        Some("1")
    );
}

#[tokio::test]
async fn multi_fragment_request_completes_and_emits_response_frames() {
    let pipeline = Pipeline::new(vec![Box::new(TerminateModule {
        status: 204,
        headers: BTreeMap::new(),
        body: Vec::new(),
    })]);

    let mut deps = TestDeps {
        decoder: new_decoder(),
        encoder: new_encoder(),
        pipeline: &pipeline,
        continued_response: HttpResponse::default(),
    };

    let stream_id = StreamId::new(1).unwrap();
    let (h, c) = headers_only_request_frame_split(stream_id);
    let mut router = Http2ConnectionRouter::new();

    let frames = router.process_frame(h, &mut deps).await.expect("process");
    assert!(frames.is_empty());

    let frames = router.process_frame(c, &mut deps).await.expect("process");
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].header.frame_type, FrameType::Headers);

    let FramePayload::Headers(block) = &frames[0].payload else {
        panic!("expected HEADERS payload");
    };
    let mut resp_decoder = new_decoder();
    let fields = decode_header_block(
        &mut resp_decoder,
        HeaderBlockInput {
            first_fragment: block,
            continuation_fragments: &[],
        },
    )
    .expect("decode");
    let resp = map_headers_to_response(&fields).expect("map");
    assert_eq!(resp.status, Some(204));
}

#[tokio::test]
async fn multi_stream_isolation_interleaving_produces_responses_per_stream() {
    let pipeline = Pipeline::new(vec![Box::new(TerminateModule {
        status: 200,
        headers: BTreeMap::new(),
        body: Vec::new(),
    })]);

    let mut deps = TestDeps {
        decoder: new_decoder(),
        encoder: new_encoder(),
        pipeline: &pipeline,
        continued_response: HttpResponse::default(),
    };

    let s1 = StreamId::new(1).unwrap();
    let s3 = StreamId::new(3).unwrap();
    let (s1_h, s1_c) = headers_only_request_frame_split(s1);
    let (s3_h, s3_c) = headers_only_request_frame_split(s3);

    let mut router = Http2ConnectionRouter::new();

    // Interleave: start both, then complete stream 1.
    assert!(router
        .process_frame(s1_h, &mut deps)
        .await
        .expect("process")
        .is_empty());
    assert!(router
        .process_frame(s3_h, &mut deps)
        .await
        .expect("process")
        .is_empty());

    let s1_resp = router
        .process_frame(s1_c, &mut deps)
        .await
        .expect("process");
    assert_eq!(s1_resp.len(), 1);
    assert_eq!(s1_resp[0].header.stream_id, s1);

    let s3_resp = router
        .process_frame(s3_c, &mut deps)
        .await
        .expect("process");
    assert_eq!(s3_resp.len(), 1);
    assert_eq!(s3_resp[0].header.stream_id, s3);
}
