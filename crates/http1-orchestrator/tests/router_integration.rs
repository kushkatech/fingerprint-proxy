use fingerprint_proxy_core::connection::{ConnectionContext, TransportProtocol};
use fingerprint_proxy_core::enrichment::ModuleDecision;
use fingerprint_proxy_core::error::{ErrorKind, FpError, FpResult};
use fingerprint_proxy_core::fingerprint::{Fingerprint, FingerprintAvailability, FingerprintKind};
use fingerprint_proxy_core::fingerprinting::FingerprintComputationResult;
use fingerprint_proxy_core::identifiers::{ConfigVersion, ConnectionId, RequestId};
use fingerprint_proxy_core::request::{HttpRequest, HttpResponse, RequestContext};
use fingerprint_proxy_http1::request::ParseOptions;
use fingerprint_proxy_http1::response::parse_http1_response;
use fingerprint_proxy_http1_orchestrator::{
    AssemblerInput, Http1ConnectionRouter, Http1ProcessOutput, Http1RouterDeps,
};
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

fn split_http1_message(raw: &[u8]) -> (&[u8], &[u8]) {
    let idx = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("response contains header terminator");
    (&raw[..idx + 4], &raw[idx + 4..])
}

fn expect_responses(output: Http1ProcessOutput) -> Vec<Vec<u8>> {
    match output {
        Http1ProcessOutput::Responses(responses) => responses,
        Http1ProcessOutput::WebSocketUpgrade(_) => panic!("expected HTTP/1 responses"),
    }
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

struct TerminateWithTrailers {
    trailers: BTreeMap<String, String>,
    body: Vec<u8>,
}

impl PipelineModule for TerminateWithTrailers {
    fn name(&self) -> &'static str {
        "terminate-with-trailers"
    }

    fn handle(&self, ctx: &mut RequestContext) -> PipelineModuleResult {
        set_response_status(ctx, 200);
        ctx.response.trailers = self.trailers.clone();
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
    pipeline: &'a Pipeline,
}

impl Http1RouterDeps for TestDeps<'_> {
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
                "STUB[T289]: HTTP/1 upstream is not implemented",
            ))
        })
    }
}

#[tokio::test]
async fn router_happy_path_request_ready_runs_pipeline_and_returns_serialized_response() {
    let mut headers = BTreeMap::new();
    headers.insert("Content-Type".to_string(), "text/plain".to_string());

    let pipeline = Pipeline::new(vec![Box::new(TerminateModule {
        status: 200,
        headers,
        body: b"abc".to_vec(),
    })]);
    let deps = TestDeps {
        pipeline: &pipeline,
    };

    let req_bytes = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let mut router = Http1ConnectionRouter::new();
    let out = router
        .process(AssemblerInput::Bytes(req_bytes), &deps)
        .await
        .expect("process");
    let out = expect_responses(out);
    assert_eq!(out.len(), 1);

    let (head, body) = split_http1_message(&out[0]);
    let resp = parse_http1_response(head, ParseOptions::default()).expect("parse");
    assert_eq!(resp.status, Some(200));
    assert_eq!(
        resp.headers.get("Content-Type").map(String::as_str),
        Some("text/plain")
    );
    assert_eq!(body, b"abc");
}

#[tokio::test]
async fn router_response_with_trailers_is_chunked_and_appends_trailer_block() {
    let mut trailers = BTreeMap::new();
    trailers.insert("X-Trailer".to_string(), "v".to_string());

    let pipeline = Pipeline::new(vec![Box::new(TerminateWithTrailers {
        trailers,
        body: b"abc".to_vec(),
    })]);
    let deps = TestDeps {
        pipeline: &pipeline,
    };

    let req_bytes = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let mut router = Http1ConnectionRouter::new();
    let out = router
        .process(AssemblerInput::Bytes(req_bytes), &deps)
        .await
        .expect("process");
    let out = expect_responses(out);
    assert_eq!(out.len(), 1);

    let (head, body) = split_http1_message(&out[0]);
    let resp = parse_http1_response(head, ParseOptions::default()).expect("parse");
    assert_eq!(resp.status, Some(200));
    assert_eq!(
        resp.headers.get("Transfer-Encoding").map(String::as_str),
        Some("chunked")
    );
    assert_eq!(body, b"3\r\nabc\r\n0\r\nX-Trailer: v\r\n\r\n");
    assert!(out[0].ends_with(b"\r\n\r\n"));
}

#[tokio::test]
async fn router_invalid_response_trailer_name_or_value_is_invalid_protocol_data() {
    let req_bytes = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";

    let mut trailers = BTreeMap::new();
    trailers.insert("Bad Name".to_string(), "v".to_string());
    let pipeline = Pipeline::new(vec![Box::new(TerminateWithTrailers {
        trailers,
        body: Vec::new(),
    })]);
    let deps = TestDeps {
        pipeline: &pipeline,
    };
    let mut router = Http1ConnectionRouter::new();
    let err = router
        .process(AssemblerInput::Bytes(req_bytes), &deps)
        .await
        .expect_err("must error");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);

    let mut trailers = BTreeMap::new();
    trailers.insert("X-Trailer".to_string(), "v\n".to_string());
    let pipeline = Pipeline::new(vec![Box::new(TerminateWithTrailers {
        trailers,
        body: Vec::new(),
    })]);
    let deps = TestDeps {
        pipeline: &pipeline,
    };
    let mut router = Http1ConnectionRouter::new();
    let err = router
        .process(AssemblerInput::Bytes(req_bytes), &deps)
        .await
        .expect_err("must error");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
}

#[tokio::test]
async fn router_continued_is_error() {
    let pipeline = Pipeline::new(vec![Box::new(ContinueModule)]);
    let deps = TestDeps {
        pipeline: &pipeline,
    };

    let req_bytes = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let mut router = Http1ConnectionRouter::new();
    let err = router
        .process(AssemblerInput::Bytes(req_bytes), &deps)
        .await
        .expect_err("must error");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
    assert_eq!(
        err.message,
        "STUB[T289]: HTTP/1 upstream is not implemented"
    );
}

#[tokio::test]
async fn router_pipeline_error_is_propagated() {
    let pipeline = Pipeline::new(vec![Box::new(ErrorModule)]);
    let deps = TestDeps {
        pipeline: &pipeline,
    };

    let req_bytes = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let mut router = Http1ConnectionRouter::new();
    let err = router
        .process(AssemblerInput::Bytes(req_bytes), &deps)
        .await
        .expect_err("must error");
    assert_eq!(err.message, "boom");
}

#[tokio::test]
async fn router_keep_alive_two_requests_returns_two_responses() {
    let pipeline = Pipeline::new(vec![Box::new(TerminateModule {
        status: 204,
        headers: BTreeMap::new(),
        body: Vec::new(),
    })]);
    let deps = TestDeps {
        pipeline: &pipeline,
    };

    let reqs = b"GET /1 HTTP/1.1\r\nHost: a\r\n\r\nGET /2 HTTP/1.1\r\nHost: b\r\n\r\n";
    let mut router = Http1ConnectionRouter::new();
    let out = router
        .process(AssemblerInput::Bytes(reqs), &deps)
        .await
        .expect("process");
    let out = expect_responses(out);
    assert_eq!(out.len(), 2);
}
