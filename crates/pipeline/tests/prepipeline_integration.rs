use fingerprint_proxy_core::connection::{ConnectionContext, TransportProtocol};
use fingerprint_proxy_core::enrichment::ModuleDecision;
use fingerprint_proxy_core::fingerprint::{Fingerprint, FingerprintAvailability, FingerprintKind};
use fingerprint_proxy_core::fingerprinting::FingerprintComputationResult;
use fingerprint_proxy_core::identifiers::{ConfigVersion, ConnectionId, RequestId};
use fingerprint_proxy_core::request::{HttpRequest, HttpResponse};
use fingerprint_proxy_pipeline::module::{PipelineModule, PipelineModuleResult};
use fingerprint_proxy_pipeline::Pipeline;
use fingerprint_proxy_prepipeline::{build_request_context, PrePipelineInput};
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

fn make_result(computed_at: SystemTime) -> FingerprintComputationResult {
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

struct AssertFingerprintsPresentAtStart {
    expected: FingerprintComputationResult,
}

impl PipelineModule for AssertFingerprintsPresentAtStart {
    fn name(&self) -> &'static str {
        "assert_fingerprints_present"
    }

    fn handle(
        &self,
        ctx: &mut fingerprint_proxy_core::request::RequestContext,
    ) -> PipelineModuleResult {
        let got = ctx
            .fingerprinting_result
            .as_ref()
            .expect("fingerprinting_result must be set before pipeline execution");
        assert_eq!(got, &self.expected);
        Ok(ModuleDecision::Continue)
    }
}

#[test]
fn prepipeline_builds_context_and_pipeline_sees_fingerprinting_result() {
    let computed_at = SystemTime::UNIX_EPOCH;
    let expected = make_result(computed_at);
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

    let mut ctx = build_request_context(pre).expect("pre-pipeline assembly should succeed");

    let pipeline = Pipeline::new(vec![Box::new(AssertFingerprintsPresentAtStart {
        expected,
    })]);
    let result = pipeline
        .execute(
            &mut ctx,
            fingerprint_proxy_core::enrichment::ProcessingStage::Request,
        )
        .expect("pipeline execution should succeed");
    assert_eq!(result.decision, ModuleDecision::Continue);
}
