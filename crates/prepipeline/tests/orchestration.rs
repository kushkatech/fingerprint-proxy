use fingerprint_proxy_core::connection::{ConnectionContext, TransportProtocol};
use fingerprint_proxy_core::enrichment::ModuleDecision;
use fingerprint_proxy_core::error::FpError;
use fingerprint_proxy_core::fingerprint::{Fingerprint, FingerprintAvailability, FingerprintKind};
use fingerprint_proxy_core::fingerprinting::FingerprintComputationResult;
use fingerprint_proxy_core::identifiers::{ConfigVersion, ConnectionId, RequestId};
use fingerprint_proxy_core::request::{HttpRequest, HttpResponse, PipelineModuleContext};
use fingerprint_proxy_pipeline::module::{PipelineModule, PipelineModuleResult};
use fingerprint_proxy_pipeline::response::set_response_status;
use fingerprint_proxy_pipeline::Pipeline;
use fingerprint_proxy_prepipeline::{
    run_prepared_pipeline, OrchestrationOutcome, PrePipelineInput,
};
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
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

struct SetHeaderModule {
    name: &'static str,
    deps: &'static [&'static str],
}

impl PipelineModule for SetHeaderModule {
    fn name(&self) -> &'static str {
        self.name
    }

    fn depends_on(&self) -> &'static [&'static str] {
        self.deps
    }

    fn handle(&self, ctx: &mut PipelineModuleContext<'_>) -> PipelineModuleResult {
        ctx.request.headers.insert("x-mutated".into(), "1".into());
        Ok(ModuleDecision::Continue)
    }
}

struct AssertFingerprintsPresentAtStart {
    expected: FingerprintComputationResult,
    deps: &'static [&'static str],
}

impl PipelineModule for AssertFingerprintsPresentAtStart {
    fn name(&self) -> &'static str {
        "assert_fingerprints"
    }

    fn depends_on(&self) -> &'static [&'static str] {
        self.deps
    }

    fn handle(&self, ctx: &mut PipelineModuleContext<'_>) -> PipelineModuleResult {
        let got = ctx
            .fingerprinting_result()
            .expect("fingerprinting_result must be set before pipeline execution");
        assert_eq!(got, &self.expected);
        Ok(ModuleDecision::Continue)
    }
}

struct StopModule {
    deps: &'static [&'static str],
}

impl PipelineModule for StopModule {
    fn name(&self) -> &'static str {
        "stop"
    }

    fn depends_on(&self) -> &'static [&'static str] {
        self.deps
    }

    fn handle(&self, ctx: &mut PipelineModuleContext<'_>) -> PipelineModuleResult {
        set_response_status(ctx, 418);
        Ok(ModuleDecision::Terminate)
    }
}

struct ErrorModule {
    deps: &'static [&'static str],
}

impl PipelineModule for ErrorModule {
    fn name(&self) -> &'static str {
        "err"
    }

    fn depends_on(&self) -> &'static [&'static str] {
        self.deps
    }

    fn handle(&self, _ctx: &mut PipelineModuleContext<'_>) -> PipelineModuleResult {
        Err(FpError::internal("boom"))
    }
}

struct MarkExecutedModule {
    name: &'static str,
    marker: &'static AtomicBool,
    deps: &'static [&'static str],
}

impl PipelineModule for MarkExecutedModule {
    fn name(&self) -> &'static str {
        self.name
    }

    fn depends_on(&self) -> &'static [&'static str] {
        self.deps
    }

    fn handle(&self, _ctx: &mut PipelineModuleContext<'_>) -> PipelineModuleResult {
        self.marker.store(true, Ordering::SeqCst);
        Ok(ModuleDecision::Continue)
    }
}

#[test]
fn stop_path_returns_stopped_and_does_not_execute_later_modules() {
    static NEVER_EXECUTED: AtomicBool = AtomicBool::new(false);
    NEVER_EXECUTED.store(false, Ordering::SeqCst);

    let computed_at = SystemTime::UNIX_EPOCH;
    let expected = make_fingerprinting_result(computed_at);
    let pre = PrePipelineInput {
        id: RequestId(1),
        connection: make_connection(),
        request: HttpRequest::new("GET", "/", "HTTP/1.1"),
        response: HttpResponse::default(),
        virtual_host: None,
        module_config: BTreeMap::new(),
        client_network_rules: Vec::new(),
        fingerprinting_result: expected.clone(),
    };

    let pipeline = Pipeline::new(vec![
        Box::new(SetHeaderModule {
            name: "set_header",
            deps: &[],
        }),
        Box::new(AssertFingerprintsPresentAtStart {
            expected,
            deps: &["set_header"],
        }),
        Box::new(StopModule {
            deps: &["assert_fingerprints"],
        }),
        Box::new(MarkExecutedModule {
            name: "never",
            marker: &NEVER_EXECUTED,
            deps: &[],
        }),
    ]);

    let outcome = run_prepared_pipeline(&pre, &pipeline).expect("orchestrate");
    match outcome {
        OrchestrationOutcome::Stopped { response, trace } => {
            assert_eq!(response.status, Some(418));
            let names: Vec<&str> = trace.iter().map(|t| t.module).collect();
            assert_eq!(names, vec!["set_header", "assert_fingerprints", "stop"]);
        }
        OrchestrationOutcome::Continued { .. } => panic!("expected stopped"),
    }
    assert!(!NEVER_EXECUTED.load(Ordering::SeqCst));
}

#[test]
fn continue_path_returns_ctx_with_mutations() {
    let computed_at = SystemTime::UNIX_EPOCH;
    let expected = make_fingerprinting_result(computed_at);
    let pre = PrePipelineInput {
        id: RequestId(1),
        connection: make_connection(),
        request: HttpRequest::new("GET", "/", "HTTP/1.1"),
        response: HttpResponse::default(),
        virtual_host: None,
        module_config: BTreeMap::new(),
        client_network_rules: Vec::new(),
        fingerprinting_result: expected.clone(),
    };

    let pipeline = Pipeline::new(vec![
        Box::new(SetHeaderModule {
            name: "set_header",
            deps: &[],
        }),
        Box::new(AssertFingerprintsPresentAtStart {
            expected,
            deps: &["set_header"],
        }),
    ]);

    let outcome = run_prepared_pipeline(&pre, &pipeline).expect("orchestrate");
    match outcome {
        OrchestrationOutcome::Continued { ctx, trace } => {
            assert_eq!(
                ctx.request.headers.get("x-mutated").map(String::as_str),
                Some("1")
            );
            assert!(ctx.fingerprinting_result().is_some());
            assert_eq!(trace.len(), 2);
        }
        OrchestrationOutcome::Stopped { .. } => panic!("expected continued"),
    }
}

#[test]
fn error_path_returns_error() {
    static NEVER_EXECUTED: AtomicBool = AtomicBool::new(false);
    NEVER_EXECUTED.store(false, Ordering::SeqCst);

    let computed_at = SystemTime::UNIX_EPOCH;
    let expected = make_fingerprinting_result(computed_at);
    let pre = PrePipelineInput {
        id: RequestId(1),
        connection: make_connection(),
        request: HttpRequest::new("GET", "/", "HTTP/1.1"),
        response: HttpResponse::default(),
        virtual_host: None,
        module_config: BTreeMap::new(),
        client_network_rules: Vec::new(),
        fingerprinting_result: expected,
    };

    let pipeline = Pipeline::new(vec![
        Box::new(ErrorModule { deps: &[] }),
        Box::new(MarkExecutedModule {
            name: "never",
            marker: &NEVER_EXECUTED,
            deps: &[],
        }),
    ]);

    let err = run_prepared_pipeline(&pre, &pipeline).expect_err("must error");
    assert_eq!(err.message, "boom");
    assert!(!NEVER_EXECUTED.load(Ordering::SeqCst));
}
