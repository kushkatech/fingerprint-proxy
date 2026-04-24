use crate::fingerprint_header;
use fingerprint_proxy_core::enrichment::ModuleDecision;
use fingerprint_proxy_core::error::{FpError, FpResult};
use fingerprint_proxy_core::request::RequestContext;
use fingerprint_proxy_pipeline::module::{PipelineModule, PipelineModuleResult};

pub const MODULE_NAME: &str = "forward";
const DEPENDS_ON: &[&str] = &[fingerprint_header::MODULE_NAME];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContinuedForwardProtocol {
    Http1,
    Http2,
}

#[derive(Debug, Default)]
pub struct ForwardModule;

impl ForwardModule {
    pub fn new() -> Self {
        Self
    }
}

impl PipelineModule for ForwardModule {
    fn name(&self) -> &'static str {
        MODULE_NAME
    }

    fn depends_on(&self) -> &'static [&'static str] {
        DEPENDS_ON
    }

    fn handle(&self, ctx: &mut RequestContext) -> PipelineModuleResult {
        ctx.pipeline_state.request_stage_forwarding_ready = true;
        Ok(ModuleDecision::Continue)
    }
}

pub fn ensure_pipeline_forwarding_ready(
    ctx: &RequestContext,
    protocol: ContinuedForwardProtocol,
) -> FpResult<()> {
    if !ctx.pipeline_state.request_stage_forwarding_ready {
        return Err(FpError::invalid_protocol_data(
            "continued forwarding requires forward module execution",
        ));
    }

    ensure_protocol_matches(protocol, &ctx.request.version)
}

fn ensure_protocol_matches(
    protocol: ContinuedForwardProtocol,
    request_version: &str,
) -> FpResult<()> {
    match protocol {
        ContinuedForwardProtocol::Http1 => {
            if request_version == "HTTP/1.0" || request_version == "HTTP/1.1" {
                Ok(())
            } else {
                Err(FpError::invalid_protocol_data(
                    "HTTP/1 continued forwarding requires HTTP/1.x request version",
                ))
            }
        }
        ContinuedForwardProtocol::Http2 => {
            if request_version == "HTTP/2" {
                Ok(())
            } else {
                Err(FpError::invalid_protocol_data(
                    "HTTP/2 continued forwarding requires HTTP/2 request version",
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fingerprint_proxy_core::connection::{ConnectionContext, TransportProtocol};
    use fingerprint_proxy_core::identifiers::{ConfigVersion, ConnectionId, RequestId};
    use fingerprint_proxy_core::request::HttpRequest;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::SystemTime;

    fn make_ctx(version: &str) -> RequestContext {
        let connection = ConnectionContext::new(
            ConnectionId(1),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 12345),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)), 443),
            TransportProtocol::Tcp,
            SystemTime::UNIX_EPOCH,
            ConfigVersion::new("cfg-1").expect("valid version"),
        );
        RequestContext::new(
            RequestId(1),
            connection,
            HttpRequest::new("GET", "/", version),
        )
    }

    #[test]
    fn ensure_pipeline_forwarding_ready_accepts_ready_state() {
        let mut ctx = make_ctx("HTTP/1.1");
        ForwardModule::new()
            .handle(&mut ctx)
            .expect("forward handle");
        assert!(!ctx.module_config.contains_key(MODULE_NAME));
        ensure_pipeline_forwarding_ready(&ctx, ContinuedForwardProtocol::Http1)
            .expect("must be ready");
    }

    #[test]
    fn ensure_pipeline_forwarding_ready_rejects_protocol_mismatch() {
        let mut ctx = make_ctx("HTTP/1.1");
        ForwardModule::new()
            .handle(&mut ctx)
            .expect("forward handle");
        let err = ensure_pipeline_forwarding_ready(&ctx, ContinuedForwardProtocol::Http2)
            .expect_err("mismatch");
        assert_eq!(
            err.message,
            "HTTP/2 continued forwarding requires HTTP/2 request version".to_string()
        );
    }

    #[test]
    fn ensure_pipeline_forwarding_ready_requires_forward_module() {
        let ctx = make_ctx("HTTP/1.1");
        let err = ensure_pipeline_forwarding_ready(&ctx, ContinuedForwardProtocol::Http1)
            .expect_err("missing forward module must fail");
        assert_eq!(
            err.message,
            "continued forwarding requires forward module execution".to_string()
        );
    }
}
