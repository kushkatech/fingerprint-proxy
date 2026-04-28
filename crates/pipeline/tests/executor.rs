use fingerprint_proxy_core::connection::TransportProtocol;
use fingerprint_proxy_core::enrichment::{ModuleDecision, ProcessingStage};
use fingerprint_proxy_core::error::{FpError, FpResult};
use fingerprint_proxy_core::identifiers::{ConfigVersion, ConnectionId, RequestId};
use fingerprint_proxy_core::request::{HttpRequest, PipelineModuleContext};
use fingerprint_proxy_core::{ConnectionContext, RequestContext};
use fingerprint_proxy_pipeline::executor::PipelineTraceOutcome;
use fingerprint_proxy_pipeline::module::{PipelineModule, PipelineModuleResult};
use fingerprint_proxy_pipeline::response::set_response_status;
use fingerprint_proxy_pipeline::Pipeline;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::SystemTime;

struct SetHeaderModule {
    name: &'static str,
    key: &'static str,
    value: &'static str,
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
        ctx.request
            .headers
            .insert(self.key.to_string(), self.value.to_string());
        Ok(ModuleDecision::Continue)
    }
}

struct RequireHeaderModule {
    name: &'static str,
    required_key: &'static str,
    deps: &'static [&'static str],
}

impl PipelineModule for RequireHeaderModule {
    fn name(&self) -> &'static str {
        self.name
    }

    fn depends_on(&self) -> &'static [&'static str] {
        self.deps
    }

    fn handle(&self, ctx: &mut PipelineModuleContext<'_>) -> PipelineModuleResult {
        if !ctx.request.headers.contains_key(self.required_key) {
            return Err(FpError::internal(format!(
                "missing required header: {}",
                self.required_key
            )));
        }
        Ok(ModuleDecision::Continue)
    }
}

struct StopModule {
    name: &'static str,
    status: u16,
    deps: &'static [&'static str],
}

impl PipelineModule for StopModule {
    fn name(&self) -> &'static str {
        self.name
    }

    fn depends_on(&self) -> &'static [&'static str] {
        self.deps
    }

    fn handle(&self, ctx: &mut PipelineModuleContext<'_>) -> PipelineModuleResult {
        set_response_status(ctx, self.status);
        Ok(ModuleDecision::Terminate)
    }
}

struct ErrorModule {
    name: &'static str,
    deps: &'static [&'static str],
}

impl PipelineModule for ErrorModule {
    fn name(&self) -> &'static str {
        self.name
    }

    fn depends_on(&self) -> &'static [&'static str] {
        self.deps
    }

    fn handle(&self, _ctx: &mut PipelineModuleContext<'_>) -> PipelineModuleResult {
        Err(FpError::internal("boom"))
    }
}

fn make_ctx() -> FpResult<RequestContext> {
    let client = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 12345);
    let dest = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)), 443);
    let connection = ConnectionContext::new(
        ConnectionId(1),
        client,
        dest,
        TransportProtocol::Tcp,
        SystemTime::UNIX_EPOCH,
        ConfigVersion::new("cfg-1").map_err(FpError::internal)?,
    );
    Ok(RequestContext::new(
        RequestId(2),
        connection,
        HttpRequest::new("GET", "/", "HTTP/1.1"),
    ))
}

#[test]
fn executes_modules_in_deterministic_order_with_dependencies() {
    let pipeline = Pipeline::new(vec![
        Box::new(SetHeaderModule {
            name: "a",
            key: "X-A",
            value: "1",
            deps: &[],
        }),
        Box::new(SetHeaderModule {
            name: "c",
            key: "X-C",
            value: "1",
            deps: &["a"],
        }),
        Box::new(SetHeaderModule {
            name: "b",
            key: "X-B",
            value: "1",
            deps: &["a"],
        }),
    ]);

    let mut ctx = make_ctx().unwrap();
    let result = pipeline
        .execute(&mut ctx, ProcessingStage::Request)
        .unwrap();
    let names: Vec<&str> = result.trace.iter().map(|t| t.module).collect();
    assert_eq!(names, vec!["a", "c", "b"]);
}

#[test]
fn propagates_request_mutations_between_modules() {
    let pipeline = Pipeline::new(vec![
        Box::new(SetHeaderModule {
            name: "set",
            key: "X-Test",
            value: "ok",
            deps: &[],
        }),
        Box::new(RequireHeaderModule {
            name: "require",
            required_key: "X-Test",
            deps: &[],
        }),
    ]);

    let mut ctx = make_ctx().unwrap();
    let result = pipeline
        .execute(&mut ctx, ProcessingStage::Request)
        .unwrap();
    assert_eq!(result.decision, ModuleDecision::Continue);
    assert_eq!(
        ctx.request.headers.get("X-Test").map(String::as_str),
        Some("ok")
    );
}

#[test]
fn early_terminate_stops_further_execution() {
    let pipeline = Pipeline::new(vec![
        Box::new(SetHeaderModule {
            name: "a",
            key: "X-A",
            value: "1",
            deps: &[],
        }),
        Box::new(StopModule {
            name: "stop",
            status: 418,
            deps: &[],
        }),
        Box::new(SetHeaderModule {
            name: "never",
            key: "X-Never",
            value: "1",
            deps: &[],
        }),
    ]);

    let mut ctx = make_ctx().unwrap();
    let result = pipeline
        .execute(&mut ctx, ProcessingStage::Request)
        .unwrap();
    assert_eq!(result.decision, ModuleDecision::Terminate);
    assert_eq!(ctx.response.status, Some(418));
    assert!(!ctx.request.headers.contains_key("X-Never"));
    assert_eq!(result.trace.len(), 2);
    assert_eq!(result.trace[1].outcome, PipelineTraceOutcome::Terminate);
}

#[test]
fn error_stops_execution_and_returns_error_with_trace() {
    let pipeline = Pipeline::new(vec![
        Box::new(SetHeaderModule {
            name: "a",
            key: "X-A",
            value: "1",
            deps: &[],
        }),
        Box::new(ErrorModule {
            name: "err",
            deps: &[],
        }),
        Box::new(SetHeaderModule {
            name: "never",
            key: "X-Never",
            value: "1",
            deps: &[],
        }),
    ]);

    let mut ctx = make_ctx().unwrap();
    let err = pipeline
        .execute(&mut ctx, ProcessingStage::Request)
        .unwrap_err();
    assert_eq!(err.module, "err");
    assert!(err.trace.iter().any(|t| t.module == "a"));
    assert!(!ctx.request.headers.contains_key("X-Never"));
}
