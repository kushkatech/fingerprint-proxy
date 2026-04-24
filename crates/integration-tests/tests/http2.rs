use fingerprint_proxy_core::connection::{ConnectionContext, TransportProtocol};
use fingerprint_proxy_core::enrichment::ModuleDecision;
use fingerprint_proxy_core::error::{ErrorKind, FpError, FpResult};
use fingerprint_proxy_core::fingerprint::{Fingerprint, FingerprintAvailability, FingerprintKind};
use fingerprint_proxy_core::fingerprinting::FingerprintComputationResult;
use fingerprint_proxy_core::identifiers::{ConfigVersion, ConnectionId, RequestId};
use fingerprint_proxy_core::request::{HttpRequest, HttpResponse, RequestContext};
use fingerprint_proxy_hpack::{Decoder, DecoderConfig, Encoder, EncoderConfig};
use fingerprint_proxy_http1_orchestrator::Http1RouterDeps;
use fingerprint_proxy_http2::frames::{
    serialize_frame, Frame, FrameHeader, FramePayload, FrameType,
};
use fingerprint_proxy_http2::{
    decode_header_block, map_headers_to_response, reject_http2_http1x_mismatch, HeaderBlockInput,
    HTTP1_1_VERSION, HTTP2_VERSION,
};
use fingerprint_proxy_http2_orchestrator::RouterDeps as Http2RouterDeps;
use fingerprint_proxy_http3::HeaderField;
use fingerprint_proxy_http3_orchestrator::RouterDeps as Http3RouterDeps;
use fingerprint_proxy_pipeline::module::{PipelineModule, PipelineModuleResult};
use fingerprint_proxy_pipeline::response::set_response_status;
use fingerprint_proxy_pipeline::Pipeline;
use fingerprint_proxy_prepipeline::PrePipelineInput;
use fingerprint_proxy_tls_entry::{
    DispatcherDeps, DispatcherInput, DispatcherOutput, NegotiatedAlpn, TlsEntryDispatcher,
};
use fingerprint_proxy_upstream::http2::{Http2Connector, UpstreamTransport};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, IsCa, KeyPair, PKCS_ECDSA_P256_SHA256,
};
use std::collections::BTreeMap;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

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

struct TerminateModule;

impl PipelineModule for TerminateModule {
    fn name(&self) -> &'static str {
        "terminate"
    }

    fn handle(&self, ctx: &mut RequestContext) -> PipelineModuleResult {
        set_response_status(ctx, 204);
        Ok(ModuleDecision::Terminate)
    }
}

struct DummyHttp1Deps<'a> {
    pipeline: &'a Pipeline,
}

impl Http1RouterDeps for DummyHttp1Deps<'_> {
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
    ) -> Pin<Box<dyn Future<Output = FpResult<HttpResponse>> + Send + 'a>> {
        Box::pin(async move {
            Err(FpError::invalid_protocol_data(
                "HTTP/1 path not used in HTTP/2 integration test",
            ))
        })
    }
}

struct TestHttp2Deps<'a> {
    pipeline: &'a Pipeline,
    decoder: Decoder,
    encoder: Encoder,
}

impl Http2RouterDeps for TestHttp2Deps<'_> {
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

    fn handle_continued<'a>(
        &'a mut self,
        _ctx: RequestContext,
    ) -> Pin<Box<dyn Future<Output = FpResult<HttpResponse>> + Send + 'a>> {
        Box::pin(async move {
            Err(FpError::invalid_protocol_data(
                "HTTP/2 continued path not used in this test",
            ))
        })
    }
}

struct DummyHttp3Deps<'a> {
    pipeline: &'a Pipeline,
}

impl Http3RouterDeps for DummyHttp3Deps<'_> {
    fn decode_request_headers(&self, _raw_headers: &[u8]) -> FpResult<Vec<HeaderField>> {
        Err(FpError::invalid_protocol_data(
            "HTTP/3 path not used in HTTP/2 integration test",
        ))
    }

    fn encode_response_headers(&self, _resp: &HttpResponse) -> FpResult<Vec<u8>> {
        Err(FpError::invalid_protocol_data(
            "HTTP/3 path not used in HTTP/2 integration test",
        ))
    }

    fn encode_response_trailers(&self, _trailers: &BTreeMap<String, String>) -> FpResult<Vec<u8>> {
        Err(FpError::invalid_protocol_data(
            "HTTP/3 path not used in HTTP/2 integration test",
        ))
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
    http1: DummyHttp1Deps<'a>,
    http2: TestHttp2Deps<'a>,
    http3: DummyHttp3Deps<'a>,
}

impl DispatcherDeps for TestDeps<'_> {
    fn http1(&self) -> &dyn fingerprint_proxy_http1_orchestrator::Http1RouterDeps {
        &self.http1
    }

    fn http2(&mut self) -> &mut dyn Http2RouterDeps {
        &mut self.http2
    }

    fn http3(&self) -> &dyn Http3RouterDeps {
        &self.http3
    }
}

fn make_test_deps(pipeline: &Pipeline) -> TestDeps<'_> {
    TestDeps {
        http1: DummyHttp1Deps { pipeline },
        http2: TestHttp2Deps {
            pipeline,
            decoder: Decoder::new(DecoderConfig {
                max_dynamic_table_size: 4096,
            }),
            encoder: Encoder::new(EncoderConfig {
                max_dynamic_table_size: 4096,
                use_huffman: false,
            }),
        },
        http3: DummyHttp3Deps { pipeline },
    }
}

fn h2_headers_only_request_bytes(stream_id: u32) -> Vec<u8> {
    let block = vec![
        0x82, 0x86, 0x84, 0x41, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c,
        0x65, 0x2e, 0x63, 0x6f, 0x6d,
    ];
    let frame = Frame {
        header: FrameHeader {
            length: block.len() as u32,
            frame_type: FrameType::Headers,
            flags: 0x5,
            stream_id: fingerprint_proxy_http2::StreamId::new(stream_id).expect("valid stream id"),
        },
        payload: FramePayload::Headers(block),
    };
    serialize_frame(&frame).expect("serialize frame")
}

fn h2_preface_and_frame(frame_bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(fingerprint_proxy_http2::ConnectionPreface::CLIENT_BYTES);
    out.extend_from_slice(frame_bytes);
    out
}

fn make_tls_pair(
    alpn_protocols: Vec<Vec<u8>>,
) -> (Arc<rustls::ClientConfig>, Arc<rustls::ServerConfig>, String) {
    let ca_key = KeyPair::generate(&PKCS_ECDSA_P256_SHA256).expect("ca key");
    let mut ca_params = CertificateParams::new(Vec::<String>::new());
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_pair = Some(ca_key);
    let ca_cert = Certificate::from_params(ca_params).expect("ca cert");

    let leaf_key = KeyPair::generate(&PKCS_ECDSA_P256_SHA256).expect("leaf key");
    let mut leaf_params = CertificateParams::new(vec!["localhost".to_string()]);
    leaf_params.key_pair = Some(leaf_key);
    leaf_params.alg = &PKCS_ECDSA_P256_SHA256;
    let leaf_cert = Certificate::from_params(leaf_params).expect("leaf cert");
    let leaf_der = leaf_cert
        .serialize_der_with_signer(&ca_cert)
        .expect("leaf der");
    let ca_der = ca_cert.serialize_der().expect("ca der");

    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(ca_der))
        .expect("add ca");
    let mut client = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client.alpn_protocols = vec![b"h2".to_vec()];

    let key_der = rustls::pki_types::PrivateKeyDer::try_from(leaf_cert.serialize_private_key_der())
        .expect("private key");
    let mut server = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::pki_types::CertificateDer::from(leaf_der)],
            key_der,
        )
        .expect("server cert");
    server.alpn_protocols = alpn_protocols;

    (Arc::new(client), Arc::new(server), "localhost".to_string())
}

#[tokio::test]
async fn http2_dispatcher_parser_integration_routes_headers_frame() {
    let pipeline = Pipeline::new(vec![Box::new(TerminateModule)]);
    let mut deps = make_test_deps(&pipeline);

    let frame_bytes = h2_headers_only_request_bytes(1);
    let bytes = h2_preface_and_frame(&frame_bytes);
    let split = 9usize.min(bytes.len());
    let (first, second) = bytes.split_at(split);

    let mut dispatcher = TlsEntryDispatcher::new();
    let out1 = dispatcher
        .dispatch(
            Some(&NegotiatedAlpn::Http2),
            DispatcherInput::Http2Bytes(first),
            &mut deps,
        )
        .await
        .expect("first dispatch");

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
        .expect("second dispatch");

    let DispatcherOutput::Http2Frames(frames2) = out2 else {
        panic!("expected Http2Frames");
    };
    assert!(!frames2.is_empty());

    let headers_frame = frames2
        .iter()
        .find(|f| f.header.frame_type == FrameType::Headers)
        .expect("response headers frame");
    let FramePayload::Headers(block) = &headers_frame.payload else {
        panic!("headers payload");
    };

    let mut decoder = Decoder::new(DecoderConfig {
        max_dynamic_table_size: 4096,
    });
    let fields = decode_header_block(
        &mut decoder,
        HeaderBlockInput {
            first_fragment: block,
            continuation_fragments: &[],
        },
    )
    .expect("decode headers");
    let response = map_headers_to_response(&fields).expect("map headers");
    assert_eq!(response.version, "HTTP/2");
    assert_eq!(response.status, Some(204));
}

#[tokio::test]
async fn http2_dispatcher_rejects_invalid_preface() {
    let pipeline = Pipeline::new(vec![Box::new(TerminateModule)]);
    let mut deps = make_test_deps(&pipeline);
    let mut dispatcher = TlsEntryDispatcher::new();

    let err = dispatcher
        .dispatch(
            Some(&NegotiatedAlpn::Http2),
            DispatcherInput::Http2Bytes(b"NOT-HTTP2-PREFACE"),
            &mut deps,
        )
        .await
        .expect_err("must reject invalid preface");

    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
    assert_eq!(err.message, "HTTP/2 connection preface mismatch");
}

#[test]
fn protocol_immutability_rejects_http2_http1x_conversion() {
    let err = reject_http2_http1x_mismatch(HTTP2_VERSION, HTTP1_1_VERSION)
        .expect_err("HTTP/2<->HTTP/1.x mismatch must fail");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
    assert_eq!(
        err.message,
        "HTTP/2<->HTTP/1.x mismatch is forbidden: source=HTTP/2 target=HTTP/1.1"
    );
}

#[tokio::test]
async fn upstream_http2_https_enforces_h2_alpn() {
    let (client_cfg, server_cfg, host) = make_tls_pair(Vec::new());
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let acceptor = TlsAcceptor::from(server_cfg);

    let server_task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept");
        let _tls = acceptor.accept(tcp).await.expect("tls accept");
    });

    let connector = Http2Connector::new(client_cfg);
    let err = match connector
        .connect(&host, addr.port(), UpstreamTransport::Https)
        .await
    {
        Ok(_) => panic!("must fail on ALPN mismatch"),
        Err(e) => e,
    };
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
    assert_eq!(err.message, "upstream TLS ALPN mismatch: expected h2");

    server_task.await.expect("server task");
}
