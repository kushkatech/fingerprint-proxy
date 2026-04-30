use fingerprint_proxy_core::connection::{ConnectionContext, TransportProtocol};
use fingerprint_proxy_core::enrichment::ModuleDecision;
use fingerprint_proxy_core::error::{ErrorKind, FpError, FpResult};
use fingerprint_proxy_core::fingerprint::{Fingerprint, FingerprintAvailability, FingerprintKind};
use fingerprint_proxy_core::fingerprinting::FingerprintComputationResult;
use fingerprint_proxy_core::identifiers::{ConfigVersion, ConnectionId, RequestId};
use fingerprint_proxy_core::request::{HttpRequest, HttpResponse, PipelineModuleContext};
use fingerprint_proxy_http3::{map_headers_to_response, Frame, FrameType, HeaderField};
use fingerprint_proxy_http3_orchestrator::{Http3ConnectionRouter, RouterDeps};
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

struct ContinueModule;

impl PipelineModule for ContinueModule {
    fn name(&self) -> &'static str {
        "cont"
    }

    fn handle(&self, _ctx: &mut PipelineModuleContext<'_>) -> PipelineModuleResult {
        Ok(ModuleDecision::Continue)
    }
}

struct ErrorModule;

impl PipelineModule for ErrorModule {
    fn name(&self) -> &'static str {
        "err"
    }

    fn handle(&self, _ctx: &mut PipelineModuleContext<'_>) -> PipelineModuleResult {
        Err(FpError::internal("boom"))
    }
}

struct AssertTrailersThenTerminate {
    expected_trailer: (&'static str, &'static str),
}

impl PipelineModule for AssertTrailersThenTerminate {
    fn name(&self) -> &'static str {
        "assert-trailers-then-terminate"
    }

    fn handle(&self, ctx: &mut PipelineModuleContext<'_>) -> PipelineModuleResult {
        let (k, v) = self.expected_trailer;
        let got = ctx.request.trailers.get(k).map(String::as_str);
        if got != Some(v) {
            return Err(FpError::invalid_protocol_data(format!(
                "expected trailer {k}={v}, got {got:?}"
            )));
        }
        set_response_status(ctx, 204);
        Ok(ModuleDecision::Terminate)
    }
}

struct TestDeps<'a> {
    pipeline: &'a Pipeline,
}

impl RouterDeps for TestDeps<'_> {
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

fn make_headers_request() -> Frame {
    Frame::new(
        FrameType::Headers,
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

#[test]
fn happy_path_headers_only_request_emits_headers_response() {
    let mut headers = BTreeMap::new();
    headers.insert("content-type".to_string(), "text/plain".to_string());

    let pipeline = Pipeline::new(vec![Box::new(TerminateModule {
        status: 200,
        headers,
        body: Vec::new(),
    })]);
    let deps = TestDeps {
        pipeline: &pipeline,
    };

    let mut router = Http3ConnectionRouter::new();
    assert!(router
        .process_frame(0, make_headers_request(), &deps)
        .expect("process")
        .is_empty());

    let frames = router.finish_stream(0, &deps).expect("finish");
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].frame_type, FrameType::Headers);

    let resp_fields = decode_fields(frames[0].payload_bytes()).expect("decode response fields");
    let resp = map_headers_to_response(&resp_fields).expect("map response");
    assert_eq!(resp.version, "HTTP/3");
    assert_eq!(resp.status, Some(200));
    assert_eq!(
        resp.headers.get("content-type").map(String::as_str),
        Some("text/plain")
    );
}

#[test]
fn body_path_emits_headers_and_data_response() {
    let pipeline = Pipeline::new(vec![Box::new(TerminateModule {
        status: 200,
        headers: BTreeMap::new(),
        body: b"abc".to_vec(),
    })]);
    let deps = TestDeps {
        pipeline: &pipeline,
    };

    let mut router = Http3ConnectionRouter::new();
    let _ = router
        .process_frame(0, make_headers_request(), &deps)
        .expect("process");
    let frames = router.finish_stream(0, &deps).expect("finish");
    assert_eq!(frames.len(), 2);
    assert_eq!(frames[0].frame_type, FrameType::Headers);
    assert_eq!(frames[1].frame_type, FrameType::Data);
    assert_eq!(frames[1].payload_bytes(), b"abc");
}

struct TerminateWithTrailers {
    trailers: BTreeMap<String, String>,
}

impl PipelineModule for TerminateWithTrailers {
    fn name(&self) -> &'static str {
        "terminate-with-trailers"
    }

    fn handle(&self, ctx: &mut PipelineModuleContext<'_>) -> PipelineModuleResult {
        set_response_status(ctx, 200);
        ctx.response.trailers = self.trailers.clone();
        ctx.response.body = b"abc".to_vec();
        Ok(ModuleDecision::Terminate)
    }
}

#[test]
fn response_headers_body_and_trailers_emit_headers_data_and_trailing_headers() {
    let mut trailers = BTreeMap::new();
    trailers.insert("x-trailer".to_string(), "v".to_string());

    let pipeline = Pipeline::new(vec![Box::new(TerminateWithTrailers { trailers })]);
    let deps = TestDeps {
        pipeline: &pipeline,
    };

    let mut router = Http3ConnectionRouter::new();
    let _ = router
        .process_frame(0, make_headers_request(), &deps)
        .expect("headers");
    let frames = router.finish_stream(0, &deps).expect("finish");
    assert_eq!(frames.len(), 3);
    assert_eq!(frames[0].frame_type, FrameType::Headers);
    assert_eq!(frames[1].frame_type, FrameType::Data);
    assert_eq!(frames[2].frame_type, FrameType::Headers);

    let trailer_fields = decode_fields(frames[2].payload_bytes()).expect("decode trailers");
    assert_eq!(trailer_fields.len(), 1);
    assert_eq!(trailer_fields[0].name, "x-trailer");
    assert_eq!(trailer_fields[0].value, "v");
}

struct TerminateWithTrailersNoBody {
    trailers: BTreeMap<String, String>,
}

impl PipelineModule for TerminateWithTrailersNoBody {
    fn name(&self) -> &'static str {
        "terminate-with-trailers-no-body"
    }

    fn handle(&self, ctx: &mut PipelineModuleContext<'_>) -> PipelineModuleResult {
        set_response_status(ctx, 200);
        ctx.response.trailers = self.trailers.clone();
        ctx.response.body = Vec::new();
        Ok(ModuleDecision::Terminate)
    }
}

#[test]
fn response_headers_without_body_and_with_trailers_emits_headers_then_trailers_headers() {
    let mut trailers = BTreeMap::new();
    trailers.insert("x-trailer".to_string(), "v".to_string());

    let pipeline = Pipeline::new(vec![Box::new(TerminateWithTrailersNoBody { trailers })]);
    let deps = TestDeps {
        pipeline: &pipeline,
    };

    let mut router = Http3ConnectionRouter::new();
    let _ = router
        .process_frame(0, make_headers_request(), &deps)
        .expect("headers");
    let frames = router.finish_stream(0, &deps).expect("finish");
    assert_eq!(frames.len(), 2);
    assert_eq!(frames[0].frame_type, FrameType::Headers);
    assert_eq!(frames[1].frame_type, FrameType::Headers);
}

struct TerminateWithInvalidTrailers {
    trailers: BTreeMap<String, String>,
}

impl PipelineModule for TerminateWithInvalidTrailers {
    fn name(&self) -> &'static str {
        "terminate-with-invalid-trailers"
    }

    fn handle(&self, ctx: &mut PipelineModuleContext<'_>) -> PipelineModuleResult {
        set_response_status(ctx, 200);
        ctx.response.trailers = self.trailers.clone();
        Ok(ModuleDecision::Terminate)
    }
}

#[test]
fn invalid_response_trailers_are_invalid_protocol_data() {
    let mut trailers = BTreeMap::new();
    trailers.insert("connection".to_string(), "x".to_string());
    let pipeline = Pipeline::new(vec![Box::new(TerminateWithInvalidTrailers { trailers })]);
    let deps = TestDeps {
        pipeline: &pipeline,
    };

    let mut router = Http3ConnectionRouter::new();
    let _ = router
        .process_frame(0, make_headers_request(), &deps)
        .expect("headers");
    let err = router.finish_stream(0, &deps).expect_err("must error");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);

    let mut trailers = BTreeMap::new();
    trailers.insert(":path".to_string(), "/".to_string());
    let pipeline = Pipeline::new(vec![Box::new(TerminateWithInvalidTrailers { trailers })]);
    let deps = TestDeps {
        pipeline: &pipeline,
    };
    let mut router = Http3ConnectionRouter::new();
    let _ = router
        .process_frame(0, make_headers_request(), &deps)
        .expect("headers");
    let err = router.finish_stream(0, &deps).expect_err("must error");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
}

#[test]
fn request_with_trailers_is_visible_to_pipeline() {
    let pipeline = Pipeline::new(vec![Box::new(AssertTrailersThenTerminate {
        expected_trailer: ("x-trailer", "v"),
    })]);
    let deps = TestDeps {
        pipeline: &pipeline,
    };

    let mut router = Http3ConnectionRouter::new();
    let _ = router
        .process_frame(0, make_headers_request(), &deps)
        .expect("headers");
    let _ = router
        .process_frame(0, Frame::new(FrameType::Data, b"abc".to_vec()), &deps)
        .expect("data");
    let _ = router
        .process_frame(
            0,
            Frame::new(
                FrameType::Headers,
                encode_fields(&[HeaderField {
                    name: "x-trailer".to_string(),
                    value: "v".to_string(),
                }]),
            ),
            &deps,
        )
        .expect("trailers headers");

    let frames = router.finish_stream(0, &deps).expect("finish");
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].frame_type, FrameType::Headers);

    let resp_fields = decode_fields(frames[0].payload_bytes()).expect("decode response fields");
    let resp = map_headers_to_response(&resp_fields).expect("map response");
    assert_eq!(resp.status, Some(204));
}

#[test]
fn trailers_with_pseudo_header_is_invalid_protocol_data() {
    let pipeline = Pipeline::new(vec![Box::new(TerminateModule {
        status: 204,
        headers: BTreeMap::new(),
        body: Vec::new(),
    })]);
    let deps = TestDeps {
        pipeline: &pipeline,
    };

    let mut router = Http3ConnectionRouter::new();
    let _ = router
        .process_frame(0, make_headers_request(), &deps)
        .expect("headers");
    let _ = router
        .process_frame(0, Frame::new(FrameType::Data, b"abc".to_vec()), &deps)
        .expect("data");
    let _ = router
        .process_frame(
            0,
            Frame::new(
                FrameType::Headers,
                encode_fields(&[HeaderField {
                    name: ":path".to_string(),
                    value: "/".to_string(),
                }]),
            ),
            &deps,
        )
        .expect("trailers headers");

    let err = router.finish_stream(0, &deps).expect_err("must error");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
}

#[test]
fn pipeline_error_is_propagated() {
    let pipeline = Pipeline::new(vec![Box::new(ErrorModule)]);
    let deps = TestDeps {
        pipeline: &pipeline,
    };

    let mut router = Http3ConnectionRouter::new();
    let _ = router
        .process_frame(0, make_headers_request(), &deps)
        .expect("process");
    let err = router.finish_stream(0, &deps).expect_err("must error");
    assert_eq!(err.message, "boom");
}

#[test]
fn continued_path_is_error() {
    let pipeline = Pipeline::new(vec![Box::new(ContinueModule)]);
    let deps = TestDeps {
        pipeline: &pipeline,
    };

    let mut router = Http3ConnectionRouter::new();
    let _ = router
        .process_frame(0, make_headers_request(), &deps)
        .expect("process");
    let err = router.finish_stream(0, &deps).expect_err("must error");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
    assert_eq!(
        err.message,
        "HTTP/3 continued forwarding requires the async runtime boundary"
    );
}

#[test]
fn multi_stream_isolation_interleaving_produces_responses_per_stream() {
    let pipeline = Pipeline::new(vec![Box::new(TerminateModule {
        status: 204,
        headers: BTreeMap::new(),
        body: Vec::new(),
    })]);
    let deps = TestDeps {
        pipeline: &pipeline,
    };

    let mut router = Http3ConnectionRouter::new();
    let _ = router
        .process_frame(0, make_headers_request(), &deps)
        .expect("s1 headers");
    let _ = router
        .process_frame(4, make_headers_request(), &deps)
        .expect("s3 headers");

    let out1 = router.finish_stream(0, &deps).expect("finish s1");
    assert_eq!(out1.len(), 1);

    let out3 = router.finish_stream(4, &deps).expect("finish s3");
    assert_eq!(out3.len(), 1);
}

#[test]
fn invalid_request_stream_id_is_rejected_deterministically() {
    let pipeline = Pipeline::new(vec![Box::new(TerminateModule {
        status: 204,
        headers: BTreeMap::new(),
        body: Vec::new(),
    })]);
    let deps = TestDeps {
        pipeline: &pipeline,
    };

    let mut router = Http3ConnectionRouter::new();
    let err = router
        .process_frame(1, make_headers_request(), &deps)
        .expect_err("must reject invalid request stream on process");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
    assert_eq!(err.message, "HTTP/3 invalid request stream id: 1");

    let err = router
        .finish_stream(1, &deps)
        .expect_err("must reject invalid request stream on finish");
    assert_eq!(err.kind, ErrorKind::InvalidProtocolData);
    assert_eq!(err.message, "HTTP/3 invalid request stream id: 1");
}
