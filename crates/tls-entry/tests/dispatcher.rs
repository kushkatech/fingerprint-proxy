use fingerprint_proxy_core::connection::{ConnectionContext, TransportProtocol};
use fingerprint_proxy_core::enrichment::ModuleDecision;
use fingerprint_proxy_core::error::{ErrorKind, FpError, FpResult};
use fingerprint_proxy_core::fingerprint::{Fingerprint, FingerprintAvailability, FingerprintKind};
use fingerprint_proxy_core::fingerprinting::FingerprintComputationResult;
use fingerprint_proxy_core::identifiers::{ConfigVersion, ConnectionId, RequestId};
use fingerprint_proxy_core::request::{
    HttpRequest, HttpResponse, PipelineModuleContext, RequestContext,
};
use fingerprint_proxy_hpack::{Decoder, DecoderConfig, Encoder, EncoderConfig};
use fingerprint_proxy_http1::request::ParseOptions;
use fingerprint_proxy_http1::response::parse_http1_response;
use fingerprint_proxy_http2::frames::{
    serialize_frame, Frame as Http2Frame, FrameHeader, FramePayload, FrameType,
};
use fingerprint_proxy_http2::ConnectionPreface;
use fingerprint_proxy_http2::{
    decode_header_block, map_headers_to_response, HeaderBlockInput, StreamId,
};
use fingerprint_proxy_http3::{
    map_headers_to_response as map_h3_headers_to_response, Frame as Http3Frame,
    FrameType as Http3FrameType, HeaderField,
};
use fingerprint_proxy_pipeline::module::{PipelineModule, PipelineModuleResult};
use fingerprint_proxy_pipeline::response::set_response_status;
use fingerprint_proxy_pipeline::Pipeline;
use fingerprint_proxy_prepipeline::PrePipelineInput;
use fingerprint_proxy_tls_entry::{
    DispatcherDeps, DispatcherInput, DispatcherOutput, NegotiatedAlpn, TlsEntryDispatcher,
};
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
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

fn split_http1_message(raw: &[u8]) -> (&[u8], &[u8]) {
    let idx = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("response contains header terminator");
    (&raw[..idx + 4], &raw[idx + 4..])
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

    fn handle(&self, ctx: &mut PipelineModuleContext<'_>) -> PipelineModuleResult {
        set_response_status(ctx, self.status);
        ctx.response.headers = self.headers.clone();
        ctx.response.body = self.body.clone();
        Ok(ModuleDecision::Terminate)
    }
}

struct TestHttp1Deps<'a> {
    pipeline: &'a Pipeline,
}

impl fingerprint_proxy_http1_orchestrator::Http1RouterDeps for TestHttp1Deps<'_> {
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

    fn handle_continued<'a>(
        &'a self,
        _ctx: RequestContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = FpResult<HttpResponse>> + Send + 'a>>
    {
        Box::pin(async move {
            Err(FpError::invalid_protocol_data(
                "test upstream handler rejected continued request",
            ))
        })
    }
}

struct TestHttp2Deps<'a> {
    pipeline: &'a Pipeline,
    decoder: Decoder,
    encoder: Encoder,
    requests_built: Arc<AtomicUsize>,
}

impl fingerprint_proxy_http2_orchestrator::RouterDeps for TestHttp2Deps<'_> {
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
        self.requests_built.fetch_add(1, Ordering::SeqCst);
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

    fn spawn_continued(
        &mut self,
        _stream_id: fingerprint_proxy_http2::StreamId,
        _ctx: RequestContext,
    ) -> FpResult<()> {
        Err(FpError::invalid_protocol_data(
            "HTTP/2 continued path is not used in this dispatcher test",
        ))
    }
}

fn encode_fields(fields: &[HeaderField]) -> Vec<u8> {
    let mut out = Vec::new();
    for f in fields {
        out.extend_from_slice(f.name.as_bytes());
        out.push(0);
        out.extend_from_slice(f.value.as_bytes());
        out.push(0);
    }
    out
}

fn decode_fields(raw: &[u8]) -> FpResult<Vec<HeaderField>> {
    let mut out = Vec::new();
    let mut parts = raw.split(|&b| b == 0);
    while let Some(name_bytes) = parts.next() {
        if name_bytes.is_empty() {
            break;
        }
        let Some(value_bytes) = parts.next() else {
            return Err(FpError::invalid_protocol_data("truncated header field"));
        };
        let name = std::str::from_utf8(name_bytes)
            .map_err(|_| FpError::invalid_protocol_data("header name must be utf8"))?
            .to_string();
        let value = std::str::from_utf8(value_bytes)
            .map_err(|_| FpError::invalid_protocol_data("header value must be utf8"))?
            .to_string();
        out.push(HeaderField { name, value });
    }
    Ok(out)
}

struct TestHttp3Deps<'a> {
    pipeline: &'a Pipeline,
}

impl fingerprint_proxy_http3_orchestrator::RouterDeps for TestHttp3Deps<'_> {
    fn decode_request_headers(&self, raw_headers: &[u8]) -> FpResult<Vec<HeaderField>> {
        decode_fields(raw_headers)
    }

    fn encode_response_headers(&self, resp: &HttpResponse) -> FpResult<Vec<u8>> {
        let status = resp
            .status
            .ok_or_else(|| FpError::invalid_protocol_data("missing response status"))?;
        let mut fields = Vec::new();
        fields.push(HeaderField {
            name: ":status".to_string(),
            value: format!("{status:03}"),
        });
        for (k, v) in &resp.headers {
            fields.push(HeaderField {
                name: k.clone(),
                value: v.clone(),
            });
        }
        Ok(encode_fields(&fields))
    }

    fn encode_response_trailers(&self, trailers: &BTreeMap<String, String>) -> FpResult<Vec<u8>> {
        let mut fields = Vec::new();
        for (k, v) in trailers {
            fields.push(HeaderField {
                name: k.clone(),
                value: v.clone(),
            });
        }
        Ok(encode_fields(&fields))
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
}

struct TestDeps<'a> {
    http1: TestHttp1Deps<'a>,
    http2: TestHttp2Deps<'a>,
    http3: TestHttp3Deps<'a>,
}

impl DispatcherDeps for TestDeps<'_> {
    fn http1(&self) -> &dyn fingerprint_proxy_http1_orchestrator::Http1RouterDeps {
        &self.http1
    }

    fn http2(&mut self) -> &mut dyn fingerprint_proxy_http2_orchestrator::RouterDeps {
        &mut self.http2
    }

    fn http3(&self) -> &dyn fingerprint_proxy_http3_orchestrator::RouterDeps {
        &self.http3
    }
}

fn h2_headers_only_request_bytes(stream_id: StreamId) -> Vec<u8> {
    let block = vec![
        0x82, 0x86, 0x84, 0x41, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c,
        0x65, 0x2e, 0x63, 0x6f, 0x6d,
    ];
    let frame = Http2Frame {
        header: FrameHeader {
            length: block.len() as u32,
            frame_type: FrameType::Headers,
            flags: 0x5, // END_STREAM | END_HEADERS
            stream_id,
        },
        payload: FramePayload::Headers(block),
    };
    serialize_frame(&frame).expect("serialize")
}

fn h2_headers_open_request_bytes(stream_id: StreamId) -> Vec<u8> {
    let block = vec![
        0x82, 0x86, 0x84, 0x41, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c,
        0x65, 0x2e, 0x63, 0x6f, 0x6d,
    ];
    let frame = Http2Frame {
        header: FrameHeader {
            length: block.len() as u32,
            frame_type: FrameType::Headers,
            flags: 0x4, // END_HEADERS
            stream_id,
        },
        payload: FramePayload::Headers(block),
    };
    serialize_frame(&frame).expect("serialize")
}

fn h2_preface_and_frames_bytes(frames: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(ConnectionPreface::CLIENT_BYTES);
    for f in frames {
        out.extend_from_slice(f);
    }
    out
}

fn h2_settings_frame_bytes(ack: bool) -> Vec<u8> {
    let frame = Http2Frame {
        header: FrameHeader {
            length: 0,
            frame_type: FrameType::Settings,
            flags: if ack { 0x1 } else { 0x0 },
            stream_id: StreamId::connection(),
        },
        payload: FramePayload::Settings {
            ack,
            settings: fingerprint_proxy_http2::Settings::new(Vec::new()),
        },
    };
    serialize_frame(&frame).expect("serialize SETTINGS")
}

fn h2_ping_frame_bytes(ack: bool, opaque: [u8; 8]) -> Vec<u8> {
    let frame = Http2Frame {
        header: FrameHeader {
            length: 8,
            frame_type: FrameType::Ping,
            flags: if ack { 0x1 } else { 0x0 },
            stream_id: StreamId::connection(),
        },
        payload: FramePayload::Ping { ack, opaque },
    };
    serialize_frame(&frame).expect("serialize PING")
}

fn h2_goaway_frame_bytes(last_stream_id: StreamId) -> Vec<u8> {
    let frame = Http2Frame {
        header: FrameHeader {
            length: 8,
            frame_type: FrameType::GoAway,
            flags: 0,
            stream_id: StreamId::connection(),
        },
        payload: FramePayload::GoAway {
            last_stream_id,
            error_code: 0,
            debug_data: Vec::new(),
        },
    };
    serialize_frame(&frame).expect("serialize GOAWAY")
}

fn h2_rst_stream_frame_bytes(stream_id: StreamId) -> Vec<u8> {
    let frame = Http2Frame {
        header: FrameHeader {
            length: 4,
            frame_type: FrameType::RstStream,
            flags: 0,
            stream_id,
        },
        payload: FramePayload::RstStream { error_code: 0 },
    };
    serialize_frame(&frame).expect("serialize RST_STREAM")
}

fn h2_push_promise_frame_bytes(stream_id: StreamId, promised_stream_id: StreamId) -> Vec<u8> {
    let mut payload = promised_stream_id.as_u32().to_be_bytes().to_vec();
    payload.extend_from_slice(&[0x82]);
    let frame = Http2Frame {
        header: FrameHeader {
            length: payload.len() as u32,
            frame_type: FrameType::PushPromise,
            flags: 0x4,
            stream_id,
        },
        payload: FramePayload::PushPromise(payload),
    };
    serialize_frame(&frame).expect("serialize PUSH_PROMISE")
}

fn h2_data_frame_bytes(stream_id: StreamId, flags: u8, payload: Vec<u8>) -> Vec<u8> {
    let frame = Http2Frame {
        header: FrameHeader {
            length: payload.len() as u32,
            frame_type: FrameType::Data,
            flags,
            stream_id,
        },
        payload: FramePayload::Data(payload),
    };
    serialize_frame(&frame).expect("serialize DATA")
}

fn make_test_deps(pipeline: &Pipeline) -> TestDeps<'_> {
    TestDeps {
        http1: TestHttp1Deps { pipeline },
        http2: TestHttp2Deps {
            pipeline,
            decoder: Decoder::new(DecoderConfig {
                max_dynamic_table_size: 4096,
            }),
            encoder: Encoder::new(EncoderConfig {
                max_dynamic_table_size: 4096,
                use_huffman: false,
            }),
            requests_built: Arc::new(AtomicUsize::new(0)),
        },
        http3: TestHttp3Deps { pipeline },
    }
}

fn make_h3_headers_request() -> Http3Frame {
    Http3Frame::new(
        Http3FrameType::Headers,
        encode_fields(&[
            HeaderField {
                name: ":method".to_string(),
                value: "GET".to_string(),
            },
            HeaderField {
                name: ":path".to_string(),
                value: "/".to_string(),
            },
            HeaderField {
                name: ":scheme".to_string(),
                value: "https".to_string(),
            },
            HeaderField {
                name: ":authority".to_string(),
                value: "example.com".to_string(),
            },
        ]),
    )
}

#[tokio::test]
async fn alpn_h1_routes_to_http1_orchestrator() {
    let pipeline = Pipeline::new(vec![Box::new(TerminateModule {
        status: 200,
        headers: BTreeMap::new(),
        body: b"abc".to_vec(),
    })]);

    let mut deps = TestDeps {
        http1: TestHttp1Deps {
            pipeline: &pipeline,
        },
        http2: TestHttp2Deps {
            pipeline: &pipeline,
            decoder: Decoder::new(DecoderConfig {
                max_dynamic_table_size: 4096,
            }),
            encoder: Encoder::new(EncoderConfig {
                max_dynamic_table_size: 4096,
                use_huffman: false,
            }),
            requests_built: Arc::new(AtomicUsize::new(0)),
        },
        http3: TestHttp3Deps {
            pipeline: &pipeline,
        },
    };

    let req_bytes = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let mut dispatcher = TlsEntryDispatcher::new();
    let out = dispatcher
        .dispatch(
            Some(&NegotiatedAlpn::Http1),
            DispatcherInput::Http1(fingerprint_proxy_http1_orchestrator::AssemblerInput::Bytes(
                req_bytes,
            )),
            &mut deps,
        )
        .await
        .expect("dispatch");

    let DispatcherOutput::Http1Responses(responses) = out else {
        panic!("expected Http1Responses");
    };
    assert_eq!(responses.len(), 1);
    let (head, body) = split_http1_message(&responses[0]);
    let resp = parse_http1_response(head, ParseOptions::default()).expect("parse");
    assert_eq!(resp.status, Some(200));
    assert_eq!(body, b"abc");
}

#[tokio::test]
async fn alpn_h2_routes_to_http2_orchestrator() {
    let mut headers = BTreeMap::new();
    headers.insert("content-type".to_string(), "text/plain".to_string());
    let pipeline = Pipeline::new(vec![Box::new(TerminateModule {
        status: 204,
        headers,
        body: Vec::new(),
    })]);

    let mut deps = TestDeps {
        http1: TestHttp1Deps {
            pipeline: &pipeline,
        },
        http2: TestHttp2Deps {
            pipeline: &pipeline,
            decoder: Decoder::new(DecoderConfig {
                max_dynamic_table_size: 4096,
            }),
            encoder: Encoder::new(EncoderConfig {
                max_dynamic_table_size: 4096,
                use_huffman: false,
            }),
            requests_built: Arc::new(AtomicUsize::new(0)),
        },
        http3: TestHttp3Deps {
            pipeline: &pipeline,
        },
    };

    let bytes = h2_preface_and_frames_bytes(&[
        h2_settings_frame_bytes(false),
        h2_headers_only_request_bytes(StreamId::new(1).unwrap()),
    ]);
    let mut dispatcher = TlsEntryDispatcher::new();
    let out = dispatcher
        .dispatch(
            Some(&NegotiatedAlpn::Http2),
            DispatcherInput::Http2Bytes(&bytes),
            &mut deps,
        )
        .await
        .expect("dispatch");

    let DispatcherOutput::Http2Frames(frames) = out else {
        panic!("expected Http2Frames");
    };
    assert!(!frames.is_empty());

    let mut decoder = Decoder::new(DecoderConfig {
        max_dynamic_table_size: 4096,
    });
    let Some(first) = frames
        .iter()
        .find(|f| f.header.frame_type == FrameType::Headers)
    else {
        panic!("expected response HEADERS frame");
    };
    let FramePayload::Headers(block) = &first.payload else {
        panic!("expected headers payload");
    };
    let fields = decode_header_block(
        &mut decoder,
        HeaderBlockInput {
            first_fragment: block,
            continuation_fragments: &[],
        },
    )
    .expect("decode");
    let resp = map_headers_to_response(&fields).expect("map");
    assert_eq!(resp.version, "HTTP/2");
    assert_eq!(resp.status, Some(204));
    assert_eq!(
        resp.headers.get("content-type").map(String::as_str),
        Some("text/plain")
    );
}

#[tokio::test]
async fn http2_preface_and_client_settings_emit_server_settings_and_ack() {
    let pipeline = Pipeline::new(vec![Box::new(TerminateModule {
        status: 204,
        headers: BTreeMap::new(),
        body: Vec::new(),
    })]);
    let request_count = Arc::new(AtomicUsize::new(0));
    let mut deps = TestDeps {
        http1: TestHttp1Deps {
            pipeline: &pipeline,
        },
        http2: TestHttp2Deps {
            pipeline: &pipeline,
            decoder: Decoder::new(DecoderConfig {
                max_dynamic_table_size: 4096,
            }),
            encoder: Encoder::new(EncoderConfig {
                max_dynamic_table_size: 4096,
                use_huffman: false,
            }),
            requests_built: Arc::clone(&request_count),
        },
        http3: TestHttp3Deps {
            pipeline: &pipeline,
        },
    };

    let bytes = h2_preface_and_frames_bytes(&[h2_settings_frame_bytes(false)]);
    let mut dispatcher = TlsEntryDispatcher::new();
    let out = dispatcher
        .dispatch(
            Some(&NegotiatedAlpn::Http2),
            DispatcherInput::Http2Bytes(&bytes),
            &mut deps,
        )
        .await
        .expect("dispatch");

    let DispatcherOutput::Http2Frames(frames) = out else {
        panic!("expected Http2Frames");
    };
    assert_eq!(frames.len(), 2);
    assert_eq!(frames[0].header.frame_type, FrameType::Settings);
    assert_eq!(frames[0].header.flags, 0);
    assert_eq!(frames[0].header.stream_id, StreamId::connection());
    assert_eq!(frames[1].header.frame_type, FrameType::Settings);
    assert_eq!(frames[1].header.flags, 0x1);
    assert_eq!(frames[1].header.stream_id, StreamId::connection());
    assert_eq!(request_count.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn http2_client_settings_ack_is_consumed_without_stream_routing() {
    let pipeline = Pipeline::new(vec![Box::new(TerminateModule {
        status: 204,
        headers: BTreeMap::new(),
        body: Vec::new(),
    })]);
    let request_count = Arc::new(AtomicUsize::new(0));
    let mut deps = TestDeps {
        http1: TestHttp1Deps {
            pipeline: &pipeline,
        },
        http2: TestHttp2Deps {
            pipeline: &pipeline,
            decoder: Decoder::new(DecoderConfig {
                max_dynamic_table_size: 4096,
            }),
            encoder: Encoder::new(EncoderConfig {
                max_dynamic_table_size: 4096,
                use_huffman: false,
            }),
            requests_built: Arc::clone(&request_count),
        },
        http3: TestHttp3Deps {
            pipeline: &pipeline,
        },
    };

    let bytes = h2_preface_and_frames_bytes(&[h2_settings_frame_bytes(false)]);
    let mut dispatcher = TlsEntryDispatcher::new();
    dispatcher
        .dispatch(
            Some(&NegotiatedAlpn::Http2),
            DispatcherInput::Http2Bytes(&bytes),
            &mut deps,
        )
        .await
        .expect("initial settings");

    let ack = h2_settings_frame_bytes(true);
    let out = dispatcher
        .dispatch(
            Some(&NegotiatedAlpn::Http2),
            DispatcherInput::Http2Bytes(&ack),
            &mut deps,
        )
        .await
        .expect("settings ack");
    let DispatcherOutput::Http2Frames(frames) = out else {
        panic!("expected Http2Frames");
    };
    assert!(frames.is_empty());
    assert_eq!(request_count.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn http2_ping_emits_ack_with_same_opaque_payload() {
    let pipeline = Pipeline::new(vec![Box::new(TerminateModule {
        status: 204,
        headers: BTreeMap::new(),
        body: Vec::new(),
    })]);
    let request_count = Arc::new(AtomicUsize::new(0));
    let mut deps = TestDeps {
        http1: TestHttp1Deps {
            pipeline: &pipeline,
        },
        http2: TestHttp2Deps {
            pipeline: &pipeline,
            decoder: Decoder::new(DecoderConfig {
                max_dynamic_table_size: 4096,
            }),
            encoder: Encoder::new(EncoderConfig {
                max_dynamic_table_size: 4096,
                use_huffman: false,
            }),
            requests_built: Arc::clone(&request_count),
        },
        http3: TestHttp3Deps {
            pipeline: &pipeline,
        },
    };

    let opaque = *b"pingpong";
    let bytes = h2_preface_and_frames_bytes(&[
        h2_settings_frame_bytes(false),
        h2_ping_frame_bytes(false, opaque),
    ]);
    let mut dispatcher = TlsEntryDispatcher::new();
    let out = dispatcher
        .dispatch(
            Some(&NegotiatedAlpn::Http2),
            DispatcherInput::Http2Bytes(&bytes),
            &mut deps,
        )
        .await
        .expect("dispatch");

    let DispatcherOutput::Http2Frames(frames) = out else {
        panic!("expected Http2Frames");
    };
    let ping_ack = frames
        .iter()
        .find(|f| f.header.frame_type == FrameType::Ping)
        .expect("PING ACK");
    assert_eq!(ping_ack.header.flags, 0x1);
    assert_eq!(ping_ack.header.stream_id, StreamId::connection());
    assert_eq!(ping_ack.payload, FramePayload::Ping { ack: true, opaque });
    assert_eq!(request_count.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn http2_ping_ack_is_consumed_without_stream_routing() {
    let pipeline = Pipeline::new(vec![Box::new(TerminateModule {
        status: 204,
        headers: BTreeMap::new(),
        body: Vec::new(),
    })]);
    let request_count = Arc::new(AtomicUsize::new(0));
    let mut deps = TestDeps {
        http1: TestHttp1Deps {
            pipeline: &pipeline,
        },
        http2: TestHttp2Deps {
            pipeline: &pipeline,
            decoder: Decoder::new(DecoderConfig {
                max_dynamic_table_size: 4096,
            }),
            encoder: Encoder::new(EncoderConfig {
                max_dynamic_table_size: 4096,
                use_huffman: false,
            }),
            requests_built: Arc::clone(&request_count),
        },
        http3: TestHttp3Deps {
            pipeline: &pipeline,
        },
    };

    let bytes = h2_preface_and_frames_bytes(&[h2_settings_frame_bytes(false)]);
    let mut dispatcher = TlsEntryDispatcher::new();
    dispatcher
        .dispatch(
            Some(&NegotiatedAlpn::Http2),
            DispatcherInput::Http2Bytes(&bytes),
            &mut deps,
        )
        .await
        .expect("initial settings");

    let ack = h2_ping_frame_bytes(true, *b"ack-ack!");
    let out = dispatcher
        .dispatch(
            Some(&NegotiatedAlpn::Http2),
            DispatcherInput::Http2Bytes(&ack),
            &mut deps,
        )
        .await
        .expect("ping ack");
    let DispatcherOutput::Http2Frames(frames) = out else {
        panic!("expected Http2Frames");
    };
    assert!(frames.is_empty());
    assert_eq!(request_count.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn http2_data_emits_connection_and_stream_window_updates() {
    let pipeline = Pipeline::new(vec![Box::new(TerminateModule {
        status: 204,
        headers: BTreeMap::new(),
        body: Vec::new(),
    })]);
    let mut deps = make_test_deps(&pipeline);
    let stream_id = StreamId::new(1).unwrap();
    let bytes = h2_preface_and_frames_bytes(&[
        h2_settings_frame_bytes(false),
        h2_headers_open_request_bytes(stream_id),
        h2_data_frame_bytes(stream_id, 0, vec![0; 1_024]),
    ]);

    let mut dispatcher = TlsEntryDispatcher::new();
    let out = dispatcher
        .dispatch(
            Some(&NegotiatedAlpn::Http2),
            DispatcherInput::Http2Bytes(&bytes),
            &mut deps,
        )
        .await
        .expect("dispatch");
    let DispatcherOutput::Http2Frames(frames) = out else {
        panic!("expected Http2Frames");
    };

    let updates: Vec<_> = frames
        .iter()
        .filter(|f| f.header.frame_type == FrameType::WindowUpdate)
        .collect();
    assert_eq!(updates.len(), 2);
    assert_eq!(updates[0].header.stream_id, StreamId::connection());
    assert_eq!(
        updates[0].payload,
        FramePayload::WindowUpdate {
            window_size_increment: 1_024,
        }
    );
    assert_eq!(updates[1].header.stream_id, stream_id);
    assert_eq!(
        updates[1].payload,
        FramePayload::WindowUpdate {
            window_size_increment: 1_024,
        }
    );
}

#[tokio::test]
async fn http2_chunked_body_larger_than_initial_window_completes_with_window_updates() {
    let pipeline = Pipeline::new(vec![Box::new(TerminateModule {
        status: 204,
        headers: BTreeMap::new(),
        body: Vec::new(),
    })]);
    let request_count = Arc::new(AtomicUsize::new(0));
    let mut deps = TestDeps {
        http1: TestHttp1Deps {
            pipeline: &pipeline,
        },
        http2: TestHttp2Deps {
            pipeline: &pipeline,
            decoder: Decoder::new(DecoderConfig {
                max_dynamic_table_size: 4096,
            }),
            encoder: Encoder::new(EncoderConfig {
                max_dynamic_table_size: 4096,
                use_huffman: false,
            }),
            requests_built: Arc::clone(&request_count),
        },
        http3: TestHttp3Deps {
            pipeline: &pipeline,
        },
    };
    let stream_id = StreamId::new(1).unwrap();
    let bytes = h2_preface_and_frames_bytes(&[
        h2_settings_frame_bytes(false),
        h2_headers_open_request_bytes(stream_id),
        h2_data_frame_bytes(stream_id, 0, vec![b'a'; 32_768]),
        h2_data_frame_bytes(stream_id, 0, vec![b'b'; 32_768]),
        h2_data_frame_bytes(stream_id, 0x1, vec![b'c'; 1]),
    ]);

    let mut dispatcher = TlsEntryDispatcher::new();
    let out = dispatcher
        .dispatch(
            Some(&NegotiatedAlpn::Http2),
            DispatcherInput::Http2Bytes(&bytes),
            &mut deps,
        )
        .await
        .expect("large chunked body completes");
    let DispatcherOutput::Http2Frames(frames) = out else {
        panic!("expected Http2Frames");
    };

    let updates: Vec<_> = frames
        .iter()
        .filter(|f| f.header.frame_type == FrameType::WindowUpdate)
        .collect();
    assert_eq!(updates.len(), 6);
    assert_eq!(request_count.load(Ordering::SeqCst), 1);
    assert!(frames
        .iter()
        .any(|f| f.header.frame_type == FrameType::Headers && f.header.stream_id == stream_id));
}

#[tokio::test]
async fn http2_goaway_prevents_new_request_routing() {
    let pipeline = Pipeline::new(vec![Box::new(TerminateModule {
        status: 204,
        headers: BTreeMap::new(),
        body: Vec::new(),
    })]);
    let request_count = Arc::new(AtomicUsize::new(0));
    let mut deps = TestDeps {
        http1: TestHttp1Deps {
            pipeline: &pipeline,
        },
        http2: TestHttp2Deps {
            pipeline: &pipeline,
            decoder: Decoder::new(DecoderConfig {
                max_dynamic_table_size: 4096,
            }),
            encoder: Encoder::new(EncoderConfig {
                max_dynamic_table_size: 4096,
                use_huffman: false,
            }),
            requests_built: Arc::clone(&request_count),
        },
        http3: TestHttp3Deps {
            pipeline: &pipeline,
        },
    };

    let bytes = h2_preface_and_frames_bytes(&[
        h2_settings_frame_bytes(false),
        h2_goaway_frame_bytes(StreamId::new(1).unwrap()),
    ]);
    let mut dispatcher = TlsEntryDispatcher::new();
    dispatcher
        .dispatch(
            Some(&NegotiatedAlpn::Http2),
            DispatcherInput::Http2Bytes(&bytes),
            &mut deps,
        )
        .await
        .expect("goaway");

    let request = h2_headers_only_request_bytes(StreamId::new(3).unwrap());
    let err = dispatcher
        .dispatch(
            Some(&NegotiatedAlpn::Http2),
            DispatcherInput::Http2Bytes(&request),
            &mut deps,
        )
        .await
        .expect_err("new request after GOAWAY must fail");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
    assert!(err.message.contains("NewStreamAfterGoAway"));
    assert_eq!(request_count.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn http2_even_client_stream_id_is_rejected_before_request_routing() {
    let pipeline = Pipeline::new(vec![Box::new(TerminateModule {
        status: 204,
        headers: BTreeMap::new(),
        body: Vec::new(),
    })]);
    let request_count = Arc::new(AtomicUsize::new(0));
    let mut deps = TestDeps {
        http1: TestHttp1Deps {
            pipeline: &pipeline,
        },
        http2: TestHttp2Deps {
            pipeline: &pipeline,
            decoder: Decoder::new(DecoderConfig {
                max_dynamic_table_size: 4096,
            }),
            encoder: Encoder::new(EncoderConfig {
                max_dynamic_table_size: 4096,
                use_huffman: false,
            }),
            requests_built: Arc::clone(&request_count),
        },
        http3: TestHttp3Deps {
            pipeline: &pipeline,
        },
    };

    let bytes = h2_preface_and_frames_bytes(&[
        h2_settings_frame_bytes(false),
        h2_headers_only_request_bytes(StreamId::new(2).unwrap()),
    ]);
    let mut dispatcher = TlsEntryDispatcher::new();
    let err = dispatcher
        .dispatch(
            Some(&NegotiatedAlpn::Http2),
            DispatcherInput::Http2Bytes(&bytes),
            &mut deps,
        )
        .await
        .expect_err("even client stream id must fail");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
    assert!(err.message.contains("InvalidClientInitiatedStreamId"));
    assert_eq!(request_count.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn http2_lower_new_client_stream_id_is_rejected_before_request_routing() {
    let pipeline = Pipeline::new(vec![Box::new(TerminateModule {
        status: 204,
        headers: BTreeMap::new(),
        body: Vec::new(),
    })]);
    let request_count = Arc::new(AtomicUsize::new(0));
    let mut deps = TestDeps {
        http1: TestHttp1Deps {
            pipeline: &pipeline,
        },
        http2: TestHttp2Deps {
            pipeline: &pipeline,
            decoder: Decoder::new(DecoderConfig {
                max_dynamic_table_size: 4096,
            }),
            encoder: Encoder::new(EncoderConfig {
                max_dynamic_table_size: 4096,
                use_huffman: false,
            }),
            requests_built: Arc::clone(&request_count),
        },
        http3: TestHttp3Deps {
            pipeline: &pipeline,
        },
    };

    let bytes = h2_preface_and_frames_bytes(&[
        h2_settings_frame_bytes(false),
        h2_headers_only_request_bytes(StreamId::new(5).unwrap()),
    ]);
    let mut dispatcher = TlsEntryDispatcher::new();
    dispatcher
        .dispatch(
            Some(&NegotiatedAlpn::Http2),
            DispatcherInput::Http2Bytes(&bytes),
            &mut deps,
        )
        .await
        .expect("stream 5 routes");
    assert_eq!(request_count.load(Ordering::SeqCst), 1);

    let lower = h2_headers_only_request_bytes(StreamId::new(3).unwrap());
    let err = dispatcher
        .dispatch(
            Some(&NegotiatedAlpn::Http2),
            DispatcherInput::Http2Bytes(&lower),
            &mut deps,
        )
        .await
        .expect_err("lower new stream id must fail");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
    assert!(err.message.contains("NonIncreasingClientStreamId"));
    assert_eq!(request_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn http2_headers_after_end_stream_are_rejected_before_request_routing() {
    let pipeline = Pipeline::new(vec![Box::new(TerminateModule {
        status: 204,
        headers: BTreeMap::new(),
        body: Vec::new(),
    })]);
    let request_count = Arc::new(AtomicUsize::new(0));
    let mut deps = TestDeps {
        http1: TestHttp1Deps {
            pipeline: &pipeline,
        },
        http2: TestHttp2Deps {
            pipeline: &pipeline,
            decoder: Decoder::new(DecoderConfig {
                max_dynamic_table_size: 4096,
            }),
            encoder: Encoder::new(EncoderConfig {
                max_dynamic_table_size: 4096,
                use_huffman: false,
            }),
            requests_built: Arc::clone(&request_count),
        },
        http3: TestHttp3Deps {
            pipeline: &pipeline,
        },
    };

    let stream_id = StreamId::new(1).unwrap();
    let bytes = h2_preface_and_frames_bytes(&[
        h2_settings_frame_bytes(false),
        h2_headers_only_request_bytes(stream_id),
    ]);
    let mut dispatcher = TlsEntryDispatcher::new();
    dispatcher
        .dispatch(
            Some(&NegotiatedAlpn::Http2),
            DispatcherInput::Http2Bytes(&bytes),
            &mut deps,
        )
        .await
        .expect("first request routes");
    assert_eq!(request_count.load(Ordering::SeqCst), 1);

    let reused = h2_headers_only_request_bytes(stream_id);
    let err = dispatcher
        .dispatch(
            Some(&NegotiatedAlpn::Http2),
            DispatcherInput::Http2Bytes(&reused),
            &mut deps,
        )
        .await
        .expect_err("reused stream after END_STREAM must fail");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
    assert!(err.message.contains("StreamAlreadyClosed"));
    assert_eq!(request_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn http2_valid_increasing_odd_client_stream_ids_still_route() {
    let pipeline = Pipeline::new(vec![Box::new(TerminateModule {
        status: 204,
        headers: BTreeMap::new(),
        body: Vec::new(),
    })]);
    let request_count = Arc::new(AtomicUsize::new(0));
    let mut deps = TestDeps {
        http1: TestHttp1Deps {
            pipeline: &pipeline,
        },
        http2: TestHttp2Deps {
            pipeline: &pipeline,
            decoder: Decoder::new(DecoderConfig {
                max_dynamic_table_size: 4096,
            }),
            encoder: Encoder::new(EncoderConfig {
                max_dynamic_table_size: 4096,
                use_huffman: false,
            }),
            requests_built: Arc::clone(&request_count),
        },
        http3: TestHttp3Deps {
            pipeline: &pipeline,
        },
    };

    let bytes = h2_preface_and_frames_bytes(&[
        h2_settings_frame_bytes(false),
        h2_headers_only_request_bytes(StreamId::new(1).unwrap()),
        h2_headers_only_request_bytes(StreamId::new(3).unwrap()),
    ]);
    let mut dispatcher = TlsEntryDispatcher::new();
    let out = dispatcher
        .dispatch(
            Some(&NegotiatedAlpn::Http2),
            DispatcherInput::Http2Bytes(&bytes),
            &mut deps,
        )
        .await
        .expect("valid increasing odd streams route");
    let DispatcherOutput::Http2Frames(frames) = out else {
        panic!("expected Http2Frames");
    };
    let response_headers_streams: Vec<u32> = frames
        .iter()
        .filter(|f| f.header.frame_type == FrameType::Headers)
        .map(|f| f.header.stream_id.as_u32())
        .collect();
    assert!(response_headers_streams.contains(&1));
    assert!(response_headers_streams.contains(&3));
    assert_eq!(request_count.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn http2_rst_stream_is_consumed_without_request_routing() {
    let pipeline = Pipeline::new(vec![Box::new(TerminateModule {
        status: 204,
        headers: BTreeMap::new(),
        body: Vec::new(),
    })]);
    let request_count = Arc::new(AtomicUsize::new(0));
    let mut deps = TestDeps {
        http1: TestHttp1Deps {
            pipeline: &pipeline,
        },
        http2: TestHttp2Deps {
            pipeline: &pipeline,
            decoder: Decoder::new(DecoderConfig {
                max_dynamic_table_size: 4096,
            }),
            encoder: Encoder::new(EncoderConfig {
                max_dynamic_table_size: 4096,
                use_huffman: false,
            }),
            requests_built: Arc::clone(&request_count),
        },
        http3: TestHttp3Deps {
            pipeline: &pipeline,
        },
    };

    let stream_id = StreamId::new(1).unwrap();
    let bytes = h2_preface_and_frames_bytes(&[
        h2_settings_frame_bytes(false),
        h2_headers_open_request_bytes(stream_id),
    ]);
    let mut dispatcher = TlsEntryDispatcher::new();
    dispatcher
        .dispatch(
            Some(&NegotiatedAlpn::Http2),
            DispatcherInput::Http2Bytes(&bytes),
            &mut deps,
        )
        .await
        .expect("open stream");

    let rst = h2_rst_stream_frame_bytes(stream_id);
    let out = dispatcher
        .dispatch(
            Some(&NegotiatedAlpn::Http2),
            DispatcherInput::Http2Bytes(&rst),
            &mut deps,
        )
        .await
        .expect("rst stream");
    let DispatcherOutput::Http2Frames(frames) = out else {
        panic!("expected Http2Frames");
    };
    assert!(frames.is_empty());
    assert_eq!(request_count.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn http2_client_push_promise_is_rejected_explicitly() {
    let pipeline = Pipeline::new(vec![Box::new(TerminateModule {
        status: 204,
        headers: BTreeMap::new(),
        body: Vec::new(),
    })]);
    let request_count = Arc::new(AtomicUsize::new(0));
    let mut deps = TestDeps {
        http1: TestHttp1Deps {
            pipeline: &pipeline,
        },
        http2: TestHttp2Deps {
            pipeline: &pipeline,
            decoder: Decoder::new(DecoderConfig {
                max_dynamic_table_size: 4096,
            }),
            encoder: Encoder::new(EncoderConfig {
                max_dynamic_table_size: 4096,
                use_huffman: false,
            }),
            requests_built: Arc::clone(&request_count),
        },
        http3: TestHttp3Deps {
            pipeline: &pipeline,
        },
    };

    let bytes = h2_preface_and_frames_bytes(&[
        h2_settings_frame_bytes(false),
        h2_push_promise_frame_bytes(StreamId::new(1).unwrap(), StreamId::new(2).unwrap()),
    ]);
    let mut dispatcher = TlsEntryDispatcher::new();
    let err = dispatcher
        .dispatch(
            Some(&NegotiatedAlpn::Http2),
            DispatcherInput::Http2Bytes(&bytes),
            &mut deps,
        )
        .await
        .expect_err("client PUSH_PROMISE must fail");

    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
    assert_eq!(
        err.message,
        "HTTP/2 client-originated PUSH_PROMISE is protocol invalid"
    );
    assert_eq!(request_count.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn http2_unexpected_second_settings_ack_is_invalid_protocol_data() {
    let pipeline = Pipeline::new(vec![Box::new(TerminateModule {
        status: 204,
        headers: BTreeMap::new(),
        body: Vec::new(),
    })]);

    let mut deps = make_test_deps(&pipeline);
    let bytes = h2_preface_and_frames_bytes(&[h2_settings_frame_bytes(false)]);
    let mut dispatcher = TlsEntryDispatcher::new();
    dispatcher
        .dispatch(
            Some(&NegotiatedAlpn::Http2),
            DispatcherInput::Http2Bytes(&bytes),
            &mut deps,
        )
        .await
        .expect("initial settings");

    let ack = h2_settings_frame_bytes(true);
    dispatcher
        .dispatch(
            Some(&NegotiatedAlpn::Http2),
            DispatcherInput::Http2Bytes(&ack),
            &mut deps,
        )
        .await
        .expect("local settings ack");

    let err = dispatcher
        .dispatch(
            Some(&NegotiatedAlpn::Http2),
            DispatcherInput::Http2Bytes(&ack),
            &mut deps,
        )
        .await
        .expect_err("second ack must fail");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
    assert!(err.message.contains("UnexpectedSettingsAck"));
}

#[tokio::test]
async fn http2_rejects_stream_frame_before_client_settings() {
    let pipeline = Pipeline::new(vec![Box::new(TerminateModule {
        status: 204,
        headers: BTreeMap::new(),
        body: Vec::new(),
    })]);

    let mut deps = make_test_deps(&pipeline);
    let bytes =
        h2_preface_and_frames_bytes(&[h2_headers_only_request_bytes(StreamId::new(1).unwrap())]);
    let mut dispatcher = TlsEntryDispatcher::new();

    let err = dispatcher
        .dispatch(
            Some(&NegotiatedAlpn::Http2),
            DispatcherInput::Http2Bytes(&bytes),
            &mut deps,
        )
        .await
        .expect_err("stream frame before client SETTINGS must fail");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
    assert_eq!(
        err.message,
        "HTTP/2 client preface must be followed by a SETTINGS frame"
    );
}

#[tokio::test]
async fn http2_bytes_split_across_calls_is_buffered_until_complete_frame() {
    let pipeline = Pipeline::new(vec![Box::new(TerminateModule {
        status: 204,
        headers: BTreeMap::new(),
        body: Vec::new(),
    })]);

    let mut deps = make_test_deps(&pipeline);
    let frame_bytes = h2_headers_only_request_bytes(StreamId::new(1).unwrap());
    let bytes = h2_preface_and_frames_bytes(&[h2_settings_frame_bytes(false), frame_bytes]);

    let split1 = 5usize.min(bytes.len());
    let (first, rest) = bytes.split_at(split1);
    let split2 = 10usize.min(rest.len());
    let (second, third) = rest.split_at(split2);

    let mut dispatcher = TlsEntryDispatcher::new();
    let out1 = dispatcher
        .dispatch(
            Some(&NegotiatedAlpn::Http2),
            DispatcherInput::Http2Bytes(first),
            &mut deps,
        )
        .await
        .expect("dispatch first");
    let DispatcherOutput::Http2Frames(frames1) = out1 else {
        panic!("expected Http2Frames");
    };
    assert!(frames1.is_empty());

    let out2 = dispatcher
        .dispatch(
            Some(&NegotiatedAlpn::Http2),
            DispatcherInput::Http2Bytes(second),
            &mut deps,
        )
        .await
        .expect("dispatch second");
    let DispatcherOutput::Http2Frames(frames2) = out2 else {
        panic!("expected Http2Frames");
    };
    assert!(frames2.is_empty());

    let out3 = dispatcher
        .dispatch(
            Some(&NegotiatedAlpn::Http2),
            DispatcherInput::Http2Bytes(third),
            &mut deps,
        )
        .await
        .expect("dispatch third");
    let DispatcherOutput::Http2Frames(frames3) = out3 else {
        panic!("expected Http2Frames");
    };
    assert!(!frames3.is_empty());
}

#[tokio::test]
async fn http2_bytes_multiple_frames_in_one_buffer_are_all_processed() {
    let pipeline = Pipeline::new(vec![Box::new(TerminateModule {
        status: 204,
        headers: BTreeMap::new(),
        body: Vec::new(),
    })]);

    let mut deps = make_test_deps(&pipeline);
    let mut dispatcher = TlsEntryDispatcher::new();

    let bytes = h2_preface_and_frames_bytes(&[
        h2_settings_frame_bytes(false),
        h2_headers_only_request_bytes(StreamId::new(1).unwrap()),
        h2_headers_only_request_bytes(StreamId::new(3).unwrap()),
    ]);

    let out = dispatcher
        .dispatch(
            Some(&NegotiatedAlpn::Http2),
            DispatcherInput::Http2Bytes(&bytes),
            &mut deps,
        )
        .await
        .expect("dispatch");

    let DispatcherOutput::Http2Frames(frames) = out else {
        panic!("expected Http2Frames");
    };

    let response_headers_streams: Vec<u32> = frames
        .iter()
        .filter(|f| f.header.frame_type == FrameType::Headers)
        .map(|f| f.header.stream_id.as_u32())
        .collect();

    assert!(response_headers_streams.contains(&1));
    assert!(response_headers_streams.contains(&3));
}

#[tokio::test]
async fn http2_bytes_leftover_partial_header_is_preserved_for_next_call() {
    let pipeline = Pipeline::new(vec![Box::new(TerminateModule {
        status: 204,
        headers: BTreeMap::new(),
        body: Vec::new(),
    })]);

    let mut deps = make_test_deps(&pipeline);
    let frame_bytes = h2_headers_only_request_bytes(StreamId::new(1).unwrap());
    let bytes = h2_preface_and_frames_bytes(&[h2_settings_frame_bytes(false), frame_bytes]);

    let split = (ConnectionPreface::CLIENT_BYTES.len() + 2).min(bytes.len());
    let (first, second) = bytes.split_at(split);

    let mut dispatcher = TlsEntryDispatcher::new();
    let out1 = dispatcher
        .dispatch(
            Some(&NegotiatedAlpn::Http2),
            DispatcherInput::Http2Bytes(first),
            &mut deps,
        )
        .await
        .expect("dispatch first");
    let DispatcherOutput::Http2Frames(frames1) = out1 else {
        panic!("expected Http2Frames");
    };
    assert_eq!(frames1.len(), 1);
    assert_eq!(frames1[0].header.frame_type, FrameType::Settings);
    assert_eq!(frames1[0].header.flags, 0);

    let out2 = dispatcher
        .dispatch(
            Some(&NegotiatedAlpn::Http2),
            DispatcherInput::Http2Bytes(second),
            &mut deps,
        )
        .await
        .expect("dispatch second");
    let DispatcherOutput::Http2Frames(frames2) = out2 else {
        panic!("expected Http2Frames");
    };
    assert!(!frames2.is_empty());
}

#[tokio::test]
async fn http2_bytes_invalid_framing_returns_invalid_protocol_data() {
    let pipeline = Pipeline::new(vec![Box::new(TerminateModule {
        status: 204,
        headers: BTreeMap::new(),
        body: Vec::new(),
    })]);

    let mut deps = make_test_deps(&pipeline);
    let mut dispatcher = TlsEntryDispatcher::new();

    // Invalid: DATA frame on stream 0 (stream_id rules violation).
    let mut invalid = Vec::new();
    invalid.extend_from_slice(ConnectionPreface::CLIENT_BYTES);
    invalid.extend_from_slice(&[0u8, 0u8, 0u8, 0x0, 0x0, 0, 0, 0, 0]);
    let err = dispatcher
        .dispatch(
            Some(&NegotiatedAlpn::Http2),
            DispatcherInput::Http2Bytes(&invalid),
            &mut deps,
        )
        .await
        .expect_err("must error");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
}

#[tokio::test]
async fn alpn_h3_routes_to_http3_orchestrator_and_finish_stream_emits_response() {
    let pipeline = Pipeline::new(vec![Box::new(TerminateModule {
        status: 204,
        headers: BTreeMap::new(),
        body: Vec::new(),
    })]);

    let mut deps = TestDeps {
        http1: TestHttp1Deps {
            pipeline: &pipeline,
        },
        http2: TestHttp2Deps {
            pipeline: &pipeline,
            decoder: Decoder::new(DecoderConfig {
                max_dynamic_table_size: 4096,
            }),
            encoder: Encoder::new(EncoderConfig {
                max_dynamic_table_size: 4096,
                use_huffman: false,
            }),
            requests_built: Arc::new(AtomicUsize::new(0)),
        },
        http3: TestHttp3Deps {
            pipeline: &pipeline,
        },
    };

    let mut dispatcher = TlsEntryDispatcher::new();
    let out = dispatcher
        .dispatch(
            Some(&NegotiatedAlpn::Http3),
            DispatcherInput::Http3Frame {
                stream_id: 0,
                frame: make_h3_headers_request(),
            },
            &mut deps,
        )
        .await
        .expect("dispatch");
    let DispatcherOutput::Http3Frames(frames) = out else {
        panic!("expected Http3Frames");
    };
    assert!(frames.is_empty());

    let out = dispatcher
        .dispatch(
            Some(&NegotiatedAlpn::Http3),
            DispatcherInput::Http3FinishStream { stream_id: 0 },
            &mut deps,
        )
        .await
        .expect("finish dispatch");
    let DispatcherOutput::Http3Frames(frames) = out else {
        panic!("expected Http3Frames");
    };
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].frame_type, Http3FrameType::Headers);

    let fields = decode_fields(frames[0].payload_bytes()).expect("decode");
    let resp = map_h3_headers_to_response(&fields).expect("map response");
    assert_eq!(resp.version, "HTTP/3");
    assert_eq!(resp.status, Some(204));
}

#[tokio::test]
async fn missing_or_unsupported_alpn_is_invalid_protocol_data() {
    let pipeline = Pipeline::new(vec![Box::new(TerminateModule {
        status: 204,
        headers: BTreeMap::new(),
        body: Vec::new(),
    })]);

    let mut deps = TestDeps {
        http1: TestHttp1Deps {
            pipeline: &pipeline,
        },
        http2: TestHttp2Deps {
            pipeline: &pipeline,
            decoder: Decoder::new(DecoderConfig {
                max_dynamic_table_size: 4096,
            }),
            encoder: Encoder::new(EncoderConfig {
                max_dynamic_table_size: 4096,
                use_huffman: false,
            }),
            requests_built: Arc::new(AtomicUsize::new(0)),
        },
        http3: TestHttp3Deps {
            pipeline: &pipeline,
        },
    };

    let req_bytes = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let mut dispatcher = TlsEntryDispatcher::new();
    let err = dispatcher
        .dispatch(
            None,
            DispatcherInput::Http1(fingerprint_proxy_http1_orchestrator::AssemblerInput::Bytes(
                req_bytes,
            )),
            &mut deps,
        )
        .await
        .expect_err("must error");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);

    let err = dispatcher
        .dispatch(
            Some(&NegotiatedAlpn::Other(b"spdy/3".to_vec())),
            DispatcherInput::Http1(fingerprint_proxy_http1_orchestrator::AssemblerInput::Bytes(
                req_bytes,
            )),
            &mut deps,
        )
        .await
        .expect_err("must error");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
}

#[tokio::test]
async fn alpn_input_mismatch_is_invalid_protocol_data() {
    let pipeline = Pipeline::new(vec![Box::new(TerminateModule {
        status: 204,
        headers: BTreeMap::new(),
        body: Vec::new(),
    })]);

    let mut deps = TestDeps {
        http1: TestHttp1Deps {
            pipeline: &pipeline,
        },
        http2: TestHttp2Deps {
            pipeline: &pipeline,
            decoder: Decoder::new(DecoderConfig {
                max_dynamic_table_size: 4096,
            }),
            encoder: Encoder::new(EncoderConfig {
                max_dynamic_table_size: 4096,
                use_huffman: false,
            }),
            requests_built: Arc::new(AtomicUsize::new(0)),
        },
        http3: TestHttp3Deps {
            pipeline: &pipeline,
        },
    };

    let mut dispatcher = TlsEntryDispatcher::new();
    let err = dispatcher
        .dispatch(
            Some(&NegotiatedAlpn::Http1),
            DispatcherInput::Http2Bytes(b""),
            &mut deps,
        )
        .await
        .expect_err("must error");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
}
