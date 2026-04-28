use fingerprint_proxy_core::connection::{ConnectionContext, TransportProtocol};
use fingerprint_proxy_core::enrichment::{
    ClientNetworkCidr, ClientNetworkClassification, ClientNetworkClassificationMatch,
    ClientNetworkClassificationRule, ProcessingStage,
};
use fingerprint_proxy_core::fingerprint::{
    Fingerprint, FingerprintAvailability, FingerprintKind, Fingerprints,
};
use fingerprint_proxy_core::fingerprinting::{
    FingerprintComputationMetadata, FingerprintComputationResult,
};
use fingerprint_proxy_core::identifiers::{ConfigVersion, ConnectionId, RequestId};
use fingerprint_proxy_core::request::{HttpRequest, RequestContext};
use fingerprint_proxy_pipeline::{PipelineRegistry, PipelineRegistryConfig};
use fingerprint_proxy_pipeline_modules::register_builtin_modules;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::SystemTime;

fn make_ctx() -> RequestContext {
    let connection = ConnectionContext::new(
        ConnectionId(1),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 12345),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)), 443),
        TransportProtocol::Tcp,
        SystemTime::UNIX_EPOCH,
        ConfigVersion::new("cfg-1").expect("valid version"),
    );
    let mut ctx = RequestContext::new(
        RequestId(1),
        connection,
        HttpRequest::new("GET", "/up", "HTTP/1.1"),
    );
    let complete = |kind, value: &str| Fingerprint {
        kind,
        availability: FingerprintAvailability::Complete,
        value: Some(value.to_string()),
        computed_at: Some(SystemTime::UNIX_EPOCH),
        failure_reason: None,
    };
    ctx = ctx.with_fingerprinting_result(FingerprintComputationResult {
        fingerprints: Fingerprints {
            ja4t: complete(FingerprintKind::Ja4T, "ja4t"),
            ja4: complete(FingerprintKind::Ja4, "ja4"),
            ja4one: complete(FingerprintKind::Ja4One, "ja4one"),
        },
        metadata: FingerprintComputationMetadata {
            computed_at: SystemTime::UNIX_EPOCH,
            ja4one_components: None,
        },
    });
    ctx.client_network_rules = vec![ClientNetworkClassificationRule {
        name: "corp".to_string(),
        cidrs: vec![ClientNetworkCidr {
            addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)),
            prefix_len: 24,
        }],
    }];
    ctx
}

#[test]
fn builtin_modules_execute_in_deterministic_order() {
    let mut registry = PipelineRegistry::new();
    register_builtin_modules(&mut registry).expect("register builtins");
    let pipeline = registry
        .build(&PipelineRegistryConfig::default())
        .expect("build");

    let mut ctx = make_ctx();
    let result = pipeline
        .execute(&mut ctx, ProcessingStage::Request)
        .expect("execute");
    let names: Vec<&str> = result.trace.iter().map(|entry| entry.module).collect();
    assert_eq!(names, vec!["fingerprint_header", "network", "forward"]);
    let fingerprint_header_idx = names
        .iter()
        .position(|name| *name == "fingerprint_header")
        .expect("fingerprint_header registered");
    let forward_idx = names
        .iter()
        .position(|name| *name == "forward")
        .expect("forward registered");
    assert!(fingerprint_header_idx < forward_idx);
    assert_eq!(
        ctx.request.headers.get("X-JA4T").map(String::as_str),
        Some("ja4t")
    );
    assert_eq!(
        ctx.enrichment.client_network_classification,
        Some(ClientNetworkClassification::Match(
            ClientNetworkClassificationMatch {
                rule_name: "corp".to_string(),
                rule_index: 0,
            }
        ))
    );
    assert!(ctx.pipeline_state.request_stage_forwarding_ready);
}
