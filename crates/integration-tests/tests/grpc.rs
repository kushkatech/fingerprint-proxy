use fingerprint_proxy_core::connection::{ConnectionContext, TransportProtocol};
use fingerprint_proxy_core::enrichment::ModuleDecision;
use fingerprint_proxy_core::error::FpResult;
use fingerprint_proxy_core::fingerprint::{Fingerprint, FingerprintAvailability, FingerprintKind};
use fingerprint_proxy_core::fingerprinting::FingerprintComputationResult;
use fingerprint_proxy_core::identifiers::{ConfigVersion, ConnectionId, RequestId};
use fingerprint_proxy_core::request::{
    HttpRequest, HttpResponse, PipelineModuleContext, RequestContext,
};
use fingerprint_proxy_grpc::parse_grpc_frames;
use fingerprint_proxy_hpack::{Decoder, DecoderConfig, Encoder, EncoderConfig};
use fingerprint_proxy_http2::frames::{Frame, FrameHeader, FramePayload, FrameType};
use fingerprint_proxy_http2::{
    decode_header_block, map_headers_to_response, HeaderBlockInput, Http2RequestStreamAssembler,
    StreamEvent, StreamId,
};
use fingerprint_proxy_http2_orchestrator::{Http2ConnectionRouter, RouterDeps};
use fingerprint_proxy_pipeline::module::{PipelineModule, PipelineModuleResult};
use fingerprint_proxy_pipeline::Pipeline;
use fingerprint_proxy_prepipeline::PrePipelineInput;
use std::collections::{BTreeMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::SystemTime;

fn grpc_frame(message: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + message.len());
    out.push(0);
    out.extend_from_slice(&(message.len() as u32).to_be_bytes());
    out.extend_from_slice(message);
    out
}

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

struct ContinueModule;

impl PipelineModule for ContinueModule {
    fn name(&self) -> &'static str {
        "continue"
    }

    fn handle(&self, _ctx: &mut PipelineModuleContext<'_>) -> PipelineModuleResult {
        Ok(ModuleDecision::Continue)
    }
}

struct TestDeps<'a> {
    decoder: Decoder,
    encoder: Encoder,
    pipeline: &'a Pipeline,
    seen_request: Option<HttpRequest>,
    continued: VecDeque<(StreamId, HttpResponse)>,
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

    fn build_prepipeline_input(&self, request: HttpRequest) -> FpResult<PrePipelineInput> {
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

    fn spawn_continued(&mut self, stream_id: StreamId, ctx: RequestContext) -> FpResult<()> {
        self.seen_request = Some(ctx.request.clone());
        let mut response = HttpResponse {
            version: "HTTP/2".to_string(),
            status: Some(200),
            ..HttpResponse::default()
        };
        response
            .headers
            .insert("content-type".to_string(), "application/grpc".to_string());
        response
            .headers
            .insert("grpc-encoding".to_string(), "identity".to_string());
        response.body = grpc_frame(b"pong");
        response
            .trailers
            .insert("grpc-status".to_string(), "0".to_string());
        self.continued.push_back((stream_id, response));
        Ok(())
    }
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

fn encode_headers(fields: &[(&str, &str)]) -> Vec<u8> {
    let mut encoder = new_encoder();
    let mut out = Vec::new();
    for (name, value) in fields {
        let field = fingerprint_proxy_hpack::HeaderField {
            name: name.as_bytes().to_vec(),
            value: value.as_bytes().to_vec(),
        };
        out.extend_from_slice(&encoder.encode_literal_without_indexing(&field));
    }
    out
}

#[tokio::test]
async fn grpc_over_http2_is_forwarded_transparently_through_router() {
    let pipeline = Pipeline::new(vec![Box::new(ContinueModule)]);
    let mut deps = TestDeps {
        decoder: new_decoder(),
        encoder: new_encoder(),
        pipeline: &pipeline,
        seen_request: None,
        continued: VecDeque::new(),
    };

    let request_body = grpc_frame(b"ping");
    let request_trailers = BTreeMap::from([(
        String::from("grpc-status-details-bin"),
        String::from("AA=="),
    )]);

    let mut assembler = Http2RequestStreamAssembler::new(StreamId::new(1).expect("stream"));
    let headers_block = encode_headers(&[
        (":method", "POST"),
        (":scheme", "https"),
        (":authority", "grpc.example.com"),
        (":path", "/svc.Method"),
        ("content-type", "application/grpc"),
        ("te", "trailers"),
        ("grpc-timeout", "100m"),
    ]);
    let headers_frame = Frame {
        header: FrameHeader {
            length: headers_block.len() as u32,
            frame_type: FrameType::Headers,
            flags: 0x4,
            stream_id: StreamId::new(1).expect("stream"),
        },
        payload: FramePayload::Headers(headers_block),
    };
    let data_frame = Frame {
        header: FrameHeader {
            length: request_body.len() as u32,
            frame_type: FrameType::Data,
            flags: 0,
            stream_id: StreamId::new(1).expect("stream"),
        },
        payload: FramePayload::Data(request_body.clone()),
    };
    let trailers_block = encode_headers(&[("grpc-status-details-bin", "AA==")]);
    let trailers_frame = Frame {
        header: FrameHeader {
            length: trailers_block.len() as u32,
            frame_type: FrameType::Headers,
            flags: 0x5,
            stream_id: StreamId::new(1).expect("stream"),
        },
        payload: FramePayload::Headers(trailers_block),
    };

    assert!(matches!(
        assembler
            .push_frame(&mut deps.decoder, headers_frame)
            .expect("headers"),
        Some(StreamEvent::RequestHeadersReady(_))
    ));
    assert!(matches!(
        assembler
        .push_frame(&mut deps.decoder, data_frame)
        .expect("data")
            .expect("data event"),
        StreamEvent::RequestBodyData {
            bytes,
            end_stream: false,
            request_complete: None,
        } if bytes == request_body
    ));
    let completed = assembler
        .push_frame(&mut deps.decoder, trailers_frame)
        .expect("trailers")
        .expect("complete event");

    let StreamEvent::RequestTrailersReady {
        request_complete: request,
        ..
    } = completed
    else {
        panic!("expected complete request");
    };
    assert_eq!(request.body, request_body);
    assert_eq!(request.trailers, request_trailers);
    assert!(parse_grpc_frames(&request.body).is_ok());

    let mut router = Http2ConnectionRouter::new();
    let input_headers = encode_headers(&[
        (":method", "POST"),
        (":scheme", "https"),
        (":authority", "grpc.example.com"),
        (":path", "/svc.Method"),
        ("content-type", "application/grpc"),
        ("te", "trailers"),
    ]);
    let mut request_bytes = Vec::new();
    request_bytes.extend_from_slice(&fingerprint_proxy_http2::ConnectionPreface::CLIENT_BYTES[..]);
    request_bytes.extend_from_slice(
        &fingerprint_proxy_http2::serialize_frame(&Frame {
            header: FrameHeader {
                length: input_headers.len() as u32,
                frame_type: FrameType::Headers,
                flags: 0x4,
                stream_id: StreamId::new(1).expect("stream"),
            },
            payload: FramePayload::Headers(input_headers),
        })
        .expect("serialize headers"),
    );
    request_bytes.extend_from_slice(
        &fingerprint_proxy_http2::serialize_frame(&Frame {
            header: FrameHeader {
                length: request_body.len() as u32,
                frame_type: FrameType::Data,
                flags: 0x1,
                stream_id: StreamId::new(1).expect("stream"),
            },
            payload: FramePayload::Data(request_body.clone()),
        })
        .expect("serialize data"),
    );

    let mut offset = fingerprint_proxy_http2::ConnectionPreface::CLIENT_BYTES.len();
    let mut emitted = Vec::new();
    while offset < request_bytes.len() {
        let (frame, consumed) =
            fingerprint_proxy_http2::parse_frame(&request_bytes[offset..]).expect("parse frame");
        offset += consumed;
        emitted.extend(
            router
                .process_frame(frame, &mut deps)
                .await
                .expect("router process"),
        );
    }

    let seen_request = deps.seen_request.as_ref().expect("continued request");
    assert_eq!(seen_request.version, "HTTP/2");
    assert_eq!(seen_request.body, request_body);

    let (stream_id, response) = deps.continued.pop_front().expect("continued response");
    emitted.extend(
        router
            .encode_response(stream_id, &response, &mut deps)
            .expect("encode continued response"),
    );

    assert_eq!(emitted.len(), 3);
    let FramePayload::Headers(headers_block) = &emitted[0].payload else {
        panic!("expected response headers");
    };
    let response_fields = decode_header_block(
        &mut new_decoder(),
        HeaderBlockInput {
            first_fragment: headers_block,
            continuation_fragments: &[],
        },
    )
    .expect("decode response headers");
    let response = map_headers_to_response(&response_fields).expect("map response");
    assert_eq!(response.status, Some(200));
    assert_eq!(
        response.headers.get("content-type").map(String::as_str),
        Some("application/grpc")
    );
    let FramePayload::Data(data) = &emitted[1].payload else {
        panic!("expected response data");
    };
    assert_eq!(data, &grpc_frame(b"pong"));
    assert!(parse_grpc_frames(data).is_ok());
    let FramePayload::Headers(trailer_block) = &emitted[2].payload else {
        panic!("expected trailer headers");
    };
    let trailer_fields = decode_header_block(
        &mut new_decoder(),
        HeaderBlockInput {
            first_fragment: trailer_block,
            continuation_fragments: &[],
        },
    )
    .expect("decode response trailers");
    assert!(trailer_fields
        .iter()
        .any(|field| field.name == "grpc-status" && field.value == "0"));
}
