use fingerprint_proxy_core::connection::{ConnectionContext, TransportProtocol};
use fingerprint_proxy_core::enrichment::ModuleDecision;
use fingerprint_proxy_core::fingerprint::{Fingerprint, FingerprintAvailability, FingerprintKind};
use fingerprint_proxy_core::fingerprinting::FingerprintComputationResult;
use fingerprint_proxy_core::identifiers::{ConfigVersion, ConnectionId, RequestId};
use fingerprint_proxy_core::request::{HttpRequest, PipelineModuleContext, RequestContext};
use fingerprint_proxy_pipeline::executor::PipelineTraceOutcome;
use fingerprint_proxy_pipeline::module::{PipelineModule, PipelineModuleResult};
use fingerprint_proxy_pipeline::Pipeline;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::SystemTime;

struct ReadAndInjectHeader;

impl PipelineModule for ReadAndInjectHeader {
    fn name(&self) -> &'static str {
        "read_and_inject_header"
    }

    fn handle(&self, ctx: &mut PipelineModuleContext<'_>) -> PipelineModuleResult {
        let result = ctx
            .fingerprinting_result()
            .expect("prepipeline must set fingerprinting_result");
        let ja4t = result
            .fingerprints
            .ja4t
            .value
            .as_deref()
            .expect("test JA4T value");
        ctx.request
            .headers
            .insert("X-Observed-JA4T".to_string(), ja4t.to_string());
        Ok(ModuleDecision::Continue)
    }
}

struct VerifyPrecomputed;

impl PipelineModule for VerifyPrecomputed {
    fn name(&self) -> &'static str {
        "verify"
    }

    fn depends_on(&self) -> &'static [&'static str] {
        &["read_and_inject_header"]
    }

    fn handle(&self, ctx: &mut PipelineModuleContext<'_>) -> PipelineModuleResult {
        let result = ctx
            .fingerprinting_result()
            .expect("prepipeline must set fingerprinting_result");
        assert_eq!(result.fingerprints.ja4t.value.as_deref(), Some("1_2-3_4_5"));
        assert_eq!(result.fingerprints.ja4.value, None);
        assert_eq!(
            result.fingerprints.ja4one.value.as_deref(),
            Some("ja4onevalue")
        );
        Ok(ModuleDecision::Continue)
    }
}

fn make_ctx() -> RequestContext {
    let client = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 12345);
    let destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)), 443);
    let connection = ConnectionContext::new(
        ConnectionId(1),
        client,
        destination,
        TransportProtocol::Tcp,
        SystemTime::UNIX_EPOCH,
        ConfigVersion::new("test").expect("test config version"),
    );
    let req = HttpRequest::new("GET", "/", "HTTP/1.1");
    let computed_at = SystemTime::UNIX_EPOCH;
    let ja4t = Fingerprint {
        kind: FingerprintKind::Ja4T,
        availability: FingerprintAvailability::Complete,
        value: Some("1_2-3_4_5".to_string()),
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
        value: Some("ja4onevalue".to_string()),
        computed_at: Some(computed_at),
        failure_reason: None,
    };
    RequestContext::new(RequestId(1), connection, req).with_fingerprinting_result(
        FingerprintComputationResult::from_parts(ja4t, ja4, ja4one, computed_at),
    )
}

#[test]
fn pipeline_modules_can_read_precomputed_fingerprints_and_enrich_request() {
    let pipeline: Pipeline = Pipeline::new(vec![
        Box::new(VerifyPrecomputed),
        Box::new(ReadAndInjectHeader),
    ]);

    let validation = pipeline.validate();
    assert!(!validation.report.has_errors());
    assert_eq!(validation.order, vec!["read_and_inject_header", "verify"]);

    let mut ctx = make_ctx();
    let result = pipeline
        .execute(
            &mut ctx,
            fingerprint_proxy_core::enrichment::ProcessingStage::Request,
        )
        .expect("pipeline execution should succeed");

    assert_eq!(result.decision, ModuleDecision::Continue);
    assert_eq!(result.trace.len(), 2);
    assert_eq!(result.trace[0].module, "read_and_inject_header");
    assert_eq!(result.trace[0].outcome, PipelineTraceOutcome::Continue);
    assert_eq!(result.trace[1].module, "verify");
    assert_eq!(result.trace[1].outcome, PipelineTraceOutcome::Continue);
    assert!(ctx.fingerprinting_result().is_some());
    assert_eq!(
        ctx.request
            .headers
            .get("X-Observed-JA4T")
            .map(String::as_str),
        Some("1_2-3_4_5")
    );
}
