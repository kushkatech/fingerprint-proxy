use fingerprint_proxy_core::connection::TransportProtocol;
use fingerprint_proxy_core::enrichment::{ModuleDecision, ProcessingStage};
use fingerprint_proxy_core::error::FpResult;
use fingerprint_proxy_core::identifiers::{ConfigVersion, ConnectionId, RequestId};
use fingerprint_proxy_core::request::{HttpRequest, PipelineModuleContext, RequestContext};
use fingerprint_proxy_core::ConnectionContext;
use fingerprint_proxy_pipeline::module::{PipelineModule, PipelineModuleResult};
use fingerprint_proxy_pipeline::{PipelineRegistry, PipelineRegistryConfig};
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::SystemTime;

struct SetHeaderModule {
    name: &'static str,
    header: &'static str,
}

impl PipelineModule for SetHeaderModule {
    fn name(&self) -> &'static str {
        self.name
    }

    fn handle(&self, ctx: &mut PipelineModuleContext<'_>) -> PipelineModuleResult {
        ctx.request
            .headers
            .insert(self.header.to_string(), "1".to_string());
        Ok(ModuleDecision::Continue)
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
        ConfigVersion::new("cfg-1").expect("valid config version"),
    );
    Ok(RequestContext::new(
        RequestId(1),
        connection,
        HttpRequest::new("GET", "/", "HTTP/1.1"),
    ))
}

#[test]
fn registry_builds_pipeline_in_registration_order_and_honors_module_enabled() {
    let mut registry = PipelineRegistry::new();
    registry
        .register("first", || {
            Box::new(SetHeaderModule {
                name: "first",
                header: "X-First",
            })
        })
        .expect("register first");
    registry
        .register("second", || {
            Box::new(SetHeaderModule {
                name: "second",
                header: "X-Second",
            })
        })
        .expect("register second");
    registry
        .register("third", || {
            Box::new(SetHeaderModule {
                name: "third",
                header: "X-Third",
            })
        })
        .expect("register third");

    let mut enabled = BTreeMap::new();
    enabled.insert("second".to_string(), false);
    let config = PipelineRegistryConfig {
        module_enabled: enabled,
    };
    let pipeline = registry.build(&config).expect("build pipeline");

    let mut ctx = make_ctx().expect("ctx");
    let result = pipeline
        .execute(&mut ctx, ProcessingStage::Request)
        .expect("execute");

    let names: Vec<&str> = result.trace.iter().map(|entry| entry.module).collect();
    assert_eq!(names, vec!["first", "third"]);
    assert!(ctx.request.headers.contains_key("X-First"));
    assert!(!ctx.request.headers.contains_key("X-Second"));
    assert!(ctx.request.headers.contains_key("X-Third"));
}

#[test]
fn registry_rejects_duplicate_module_ids() {
    let mut registry = PipelineRegistry::new();
    registry
        .register("dupe", || {
            Box::new(SetHeaderModule {
                name: "dupe",
                header: "X-A",
            })
        })
        .expect("first register");
    let err = registry
        .register("dupe", || {
            Box::new(SetHeaderModule {
                name: "dupe",
                header: "X-B",
            })
        })
        .expect_err("duplicate id must fail");
    assert_eq!(
        err.message,
        "pipeline registry duplicate module id: dupe".to_string()
    );
}

#[test]
fn registry_rejects_unknown_module_enabled_keys() {
    let mut registry = PipelineRegistry::new();
    registry
        .register("known", || {
            Box::new(SetHeaderModule {
                name: "known",
                header: "X-Known",
            })
        })
        .expect("register");

    let mut enabled = BTreeMap::new();
    enabled.insert("unknown".to_string(), true);
    let err = match registry.build(&PipelineRegistryConfig {
        module_enabled: enabled,
    }) {
        Ok(_) => panic!("unknown module id must fail"),
        Err(err) => err,
    };
    assert_eq!(
        err.message,
        "pipeline registry unknown module id in module_enabled: unknown".to_string()
    );
}
