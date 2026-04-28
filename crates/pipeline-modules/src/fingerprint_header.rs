use fingerprint_proxy_core::enrichment::ModuleDecision;
use fingerprint_proxy_core::fingerprinting::FingerprintHeaderConfig;
use fingerprint_proxy_core::prepare_pipeline_upstream_request;
use fingerprint_proxy_core::request::PipelineModuleContext;
use fingerprint_proxy_pipeline::module::{PipelineModule, PipelineModuleResult};

pub const MODULE_NAME: &str = "fingerprint_header";
pub const JA4T_HEADER_KEY: &str = "ja4t_header";
pub const JA4_HEADER_KEY: &str = "ja4_header";
pub const JA4ONE_HEADER_KEY: &str = "ja4one_header";

#[derive(Debug, Default)]
pub struct FingerprintHeaderModule;

impl FingerprintHeaderModule {
    pub fn new() -> Self {
        Self
    }
}

impl PipelineModule for FingerprintHeaderModule {
    fn name(&self) -> &'static str {
        MODULE_NAME
    }

    fn handle(&self, ctx: &mut PipelineModuleContext<'_>) -> PipelineModuleResult {
        let config = resolve_config(ctx);
        let request = prepare_pipeline_upstream_request(ctx, &config)?;
        ctx.replace_request(request);
        Ok(ModuleDecision::Continue)
    }
}

fn resolve_config(ctx: &PipelineModuleContext<'_>) -> FingerprintHeaderConfig {
    let module_cfg = ctx.module_config.get(MODULE_NAME);
    let FingerprintHeaderConfig {
        ja4t_header: default_ja4t_header,
        ja4_header: default_ja4_header,
        ja4one_header: default_ja4one_header,
    } = FingerprintHeaderConfig::default();
    FingerprintHeaderConfig {
        ja4t_header: module_cfg
            .and_then(|cfg| cfg.get(JA4T_HEADER_KEY))
            .cloned()
            .unwrap_or(default_ja4t_header),
        ja4_header: module_cfg
            .and_then(|cfg| cfg.get(JA4_HEADER_KEY))
            .cloned()
            .unwrap_or(default_ja4_header),
        ja4one_header: module_cfg
            .and_then(|cfg| cfg.get(JA4ONE_HEADER_KEY))
            .cloned()
            .unwrap_or(default_ja4one_header),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fingerprint_proxy_core::connection::{ConnectionContext, TransportProtocol};
    use fingerprint_proxy_core::fingerprint::{
        Fingerprint, FingerprintAvailability, FingerprintKind, Fingerprints,
    };
    use fingerprint_proxy_core::fingerprinting::{
        FingerprintComputationMetadata, FingerprintComputationResult,
    };
    use fingerprint_proxy_core::identifiers::{ConfigVersion, ConnectionId, RequestId};
    use fingerprint_proxy_core::request::{HttpRequest, RequestContext};
    use std::collections::BTreeMap;
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
            HttpRequest::new("GET", "/", "HTTP/1.1"),
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
        ctx
    }

    #[test]
    fn injects_default_fingerprint_headers() {
        let mut ctx = make_ctx();
        let mut module_ctx = PipelineModuleContext::new(&mut ctx);
        FingerprintHeaderModule::new()
            .handle(&mut module_ctx)
            .expect("inject");
        assert_eq!(
            ctx.request.headers.get("X-JA4T").map(String::as_str),
            Some("ja4t")
        );
        assert_eq!(
            ctx.request.headers.get("X-JA4").map(String::as_str),
            Some("ja4")
        );
        assert_eq!(
            ctx.request.headers.get("X-JA4One").map(String::as_str),
            Some("ja4one")
        );
    }

    #[test]
    fn omits_partial_or_unavailable_fingerprints_without_status_headers() {
        let mut ctx = make_ctx();
        ctx = ctx.with_fingerprinting_result(FingerprintComputationResult {
            fingerprints: Fingerprints {
                ja4t: Fingerprint {
                    kind: FingerprintKind::Ja4T,
                    availability: FingerprintAvailability::Partial,
                    value: Some("partial-ja4t".to_string()),
                    computed_at: Some(SystemTime::UNIX_EPOCH),
                    failure_reason: None,
                },
                ja4: Fingerprint {
                    kind: FingerprintKind::Ja4,
                    availability: FingerprintAvailability::Unavailable,
                    value: Some("unavailable-ja4".to_string()),
                    computed_at: Some(SystemTime::UNIX_EPOCH),
                    failure_reason: None,
                },
                ja4one: Fingerprint {
                    kind: FingerprintKind::Ja4One,
                    availability: FingerprintAvailability::Partial,
                    value: None,
                    computed_at: Some(SystemTime::UNIX_EPOCH),
                    failure_reason: None,
                },
            },
            metadata: FingerprintComputationMetadata {
                computed_at: SystemTime::UNIX_EPOCH,
                ja4one_components: None,
            },
        });

        let mut module_ctx = PipelineModuleContext::new(&mut ctx);
        FingerprintHeaderModule::new()
            .handle(&mut module_ctx)
            .expect("inject");

        assert!(
            ctx.request.headers.is_empty(),
            "partial or unavailable fingerprints must not create production or default debug headers"
        );
    }

    #[test]
    fn uses_module_configured_header_names() {
        let mut ctx = make_ctx();
        let mut cfg = BTreeMap::new();
        cfg.insert(JA4T_HEADER_KEY.to_string(), "X-Client-JA4T".to_string());
        cfg.insert(JA4_HEADER_KEY.to_string(), "X-Client-JA4".to_string());
        cfg.insert(JA4ONE_HEADER_KEY.to_string(), "X-Client-JA4One".to_string());
        ctx.module_config.insert(MODULE_NAME.to_string(), cfg);

        let mut module_ctx = PipelineModuleContext::new(&mut ctx);
        FingerprintHeaderModule::new()
            .handle(&mut module_ctx)
            .expect("inject");
        assert_eq!(
            ctx.request.headers.get("X-Client-JA4T").map(String::as_str),
            Some("ja4t")
        );
        assert_eq!(
            ctx.request.headers.get("X-Client-JA4").map(String::as_str),
            Some("ja4")
        );
        assert_eq!(
            ctx.request
                .headers
                .get("X-Client-JA4One")
                .map(String::as_str),
            Some("ja4one")
        );
    }
}
