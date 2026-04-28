use fingerprint_proxy_core::connection::{ConnectionContext, TransportProtocol};
use fingerprint_proxy_core::error::{FpError, FpResult};
use fingerprint_proxy_core::fingerprint::{Fingerprint, FingerprintAvailability, FingerprintKind};
use fingerprint_proxy_core::fingerprinting::FingerprintComputationResult;
use fingerprint_proxy_core::identifiers::{ConfigVersion, ConnectionId, RequestId};
use fingerprint_proxy_core::request::{
    HttpRequest, HttpResponse, PipelineModuleContext, RequestContext,
};
use fingerprint_proxy_hpack::{Decoder, DecoderConfig, Encoder, EncoderConfig};
use fingerprint_proxy_http1_orchestrator::Http1RouterDeps;
use fingerprint_proxy_pipeline::module::{PipelineModule, PipelineModuleResult};
use fingerprint_proxy_pipeline::Pipeline;
use fingerprint_proxy_prepipeline::PrePipelineInput;
use fingerprint_proxy_tls_entry::{
    DispatcherDeps, DispatcherInput, DispatcherOutput, NegotiatedAlpn, TlsEntryDispatcher,
};
use std::collections::BTreeMap;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::time::SystemTime;

struct ContinueModule;

impl PipelineModule for ContinueModule {
    fn name(&self) -> &'static str {
        "cont"
    }

    fn handle(&self, _ctx: &mut PipelineModuleContext<'_>) -> PipelineModuleResult {
        Ok(fingerprint_proxy_core::enrichment::ModuleDecision::Continue)
    }
}

struct TestDeps {
    http1: TestHttp1Deps,
    http2: DummyHttp2Deps,
    http3: DummyHttp3Deps,
}

struct TestHttp1Deps {
    pipeline: Pipeline,
}

impl Http1RouterDeps for TestHttp1Deps {
    fn pipeline(&self) -> &Pipeline {
        &self.pipeline
    }

    fn build_prepipeline_input(&self, request: HttpRequest) -> FpResult<PrePipelineInput> {
        Ok(PrePipelineInput {
            id: RequestId(1),
            connection: ConnectionContext::new(
                ConnectionId(1),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443),
                TransportProtocol::Tcp,
                SystemTime::UNIX_EPOCH,
                ConfigVersion::new("v1").expect("config version"),
            ),
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
                "unexpected non-websocket continued request",
            ))
        })
    }
}

struct DummyHttp2Deps {
    pipeline: Pipeline,
    decoder: Decoder,
    encoder: Encoder,
}

impl fingerprint_proxy_http2_orchestrator::RouterDeps for DummyHttp2Deps {
    fn hpack_decoder(&mut self) -> &mut Decoder {
        &mut self.decoder
    }

    fn hpack_encoder(&mut self) -> &mut Encoder {
        &mut self.encoder
    }

    fn pipeline(&self) -> &Pipeline {
        &self.pipeline
    }

    fn build_prepipeline_input(&self, request: HttpRequest) -> FpResult<PrePipelineInput> {
        Ok(PrePipelineInput {
            id: RequestId(2),
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
        Err(FpError::invalid_protocol_data("http2 unused"))
    }
}

struct DummyHttp3Deps {
    pipeline: Pipeline,
}

impl fingerprint_proxy_http3_orchestrator::RouterDeps for DummyHttp3Deps {
    fn decode_request_headers(
        &self,
        _raw_headers: &[u8],
    ) -> FpResult<Vec<fingerprint_proxy_http3::HeaderField>> {
        Err(FpError::invalid_protocol_data("http3 unused"))
    }

    fn encode_response_headers(&self, _resp: &HttpResponse) -> FpResult<Vec<u8>> {
        Err(FpError::invalid_protocol_data("http3 unused"))
    }

    fn encode_response_trailers(&self, _trailers: &BTreeMap<String, String>) -> FpResult<Vec<u8>> {
        Err(FpError::invalid_protocol_data("http3 unused"))
    }

    fn pipeline(&self) -> &Pipeline {
        &self.pipeline
    }

    fn build_prepipeline_input(&self, request: HttpRequest) -> FpResult<PrePipelineInput> {
        Ok(PrePipelineInput {
            id: RequestId(3),
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

impl DispatcherDeps for TestDeps {
    fn http1(&self) -> &dyn Http1RouterDeps {
        &self.http1
    }

    fn http2(&mut self) -> &mut dyn fingerprint_proxy_http2_orchestrator::RouterDeps {
        &mut self.http2
    }

    fn http3(&self) -> &dyn fingerprint_proxy_http3_orchestrator::RouterDeps {
        &self.http3
    }
}

#[tokio::test]
async fn tls_entry_http1_websocket_takeover_preserves_leftover_client_frame_bytes() {
    let mut deps = TestDeps {
        http1: TestHttp1Deps {
            pipeline: Pipeline::new(vec![Box::new(ContinueModule)]),
        },
        http2: DummyHttp2Deps {
            pipeline: Pipeline::new(vec![Box::new(ContinueModule)]),
            decoder: Decoder::new(DecoderConfig {
                max_dynamic_table_size: 4096,
            }),
            encoder: Encoder::new(EncoderConfig {
                max_dynamic_table_size: 4096,
                use_huffman: false,
            }),
        },
        http3: DummyHttp3Deps {
            pipeline: Pipeline::new(vec![Box::new(ContinueModule)]),
        },
    };
    let mut dispatcher = TlsEntryDispatcher::new();

    let request = concat!(
        "GET /chat HTTP/1.1\r\n",
        "Host: example.com\r\n",
        "Upgrade: websocket\r\n",
        "Connection: Upgrade\r\n",
        "Sec-WebSocket-Version: 13\r\n",
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
        "\r\n"
    )
    .as_bytes()
    .iter()
    .copied()
    .chain(masked_text_frame(b"hello"))
    .collect::<Vec<_>>();

    let out = dispatcher
        .dispatch(
            Some(&NegotiatedAlpn::Http1),
            DispatcherInput::Http1(fingerprint_proxy_http1_orchestrator::AssemblerInput::Bytes(
                &request,
            )),
            &mut deps,
        )
        .await
        .expect("dispatch succeeds");

    let DispatcherOutput::Http1WebSocketUpgrade(upgrade) = out else {
        panic!("expected Http1WebSocketUpgrade");
    };
    assert_eq!(upgrade.ctx.request.uri, "/chat");
    assert_eq!(upgrade.initial_client_bytes, masked_text_frame(b"hello"));
}

fn masked_text_frame(payload: &[u8]) -> Vec<u8> {
    let mask = [0x21, 0x22, 0x23, 0x24];
    let mut out = vec![0x81, 0x80 | payload.len() as u8];
    out.extend_from_slice(&mask);
    for (idx, byte) in payload.iter().enumerate() {
        out.push(byte ^ mask[idx % mask.len()]);
    }
    out
}

fn make_connection() -> ConnectionContext {
    ConnectionContext::new(
        ConnectionId(1),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443),
        TransportProtocol::Tcp,
        SystemTime::UNIX_EPOCH,
        ConfigVersion::new("v1").expect("config version"),
    )
}

fn make_fingerprinting_result(computed_at: SystemTime) -> FingerprintComputationResult {
    let ja4t = Fingerprint {
        kind: FingerprintKind::Ja4T,
        availability: FingerprintAvailability::Unavailable,
        value: None,
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
        availability: FingerprintAvailability::Unavailable,
        value: None,
        computed_at: Some(computed_at),
        failure_reason: None,
    };
    FingerprintComputationResult::from_parts(ja4t, ja4, ja4one, computed_at)
}
