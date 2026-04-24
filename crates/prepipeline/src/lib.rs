use fingerprint_proxy_core::enrichment::ClientNetworkClassificationRule;
use fingerprint_proxy_core::error::FpResult;
use fingerprint_proxy_core::fingerprinting::FingerprintComputationResult;
use fingerprint_proxy_core::identifiers::RequestId;
use fingerprint_proxy_core::request::{
    HttpRequest, HttpResponse, RequestContext, VirtualHostContext,
};
use std::collections::BTreeMap;

pub mod orchestration;

pub use orchestration::{run_prepared_pipeline, OrchestrationOutcome, PipelineTrace};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrePipelineInput {
    pub id: RequestId,
    pub connection: fingerprint_proxy_core::connection::ConnectionContext,
    pub request: HttpRequest,
    pub response: HttpResponse,
    pub virtual_host: Option<VirtualHostContext>,
    pub module_config: BTreeMap<String, BTreeMap<String, String>>,
    pub client_network_rules: Vec<ClientNetworkClassificationRule>,
    pub fingerprinting_result: FingerprintComputationResult,
}

pub fn build_request_context(pre: PrePipelineInput) -> FpResult<RequestContext> {
    let mut ctx = RequestContext::new(pre.id, pre.connection, pre.request);
    ctx.response = pre.response;
    ctx.virtual_host = pre.virtual_host;
    ctx.module_config = pre.module_config;
    ctx.client_network_rules = pre.client_network_rules;
    ctx.fingerprinting_result = Some(pre.fingerprinting_result);
    Ok(ctx)
}
