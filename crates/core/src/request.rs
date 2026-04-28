use crate::connection::ConnectionContext;
use crate::enrichment::{ClientNetworkClassificationRule, ProcessingStage, RequestEnrichment};
use crate::fingerprinting::FingerprintComputationResult;
use crate::identifiers::{RequestId, VirtualHostId};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    pub method: String,
    pub uri: String,
    pub version: String,
    pub headers: BTreeMap<String, String>,
    pub trailers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

impl HttpRequest {
    pub fn new(
        method: impl Into<String>,
        uri: impl Into<String>,
        version: impl Into<String>,
    ) -> Self {
        Self {
            method: method.into(),
            uri: uri.into(),
            version: version.into(),
            headers: BTreeMap::new(),
            trailers: BTreeMap::new(),
            body: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HttpResponse {
    pub version: String,
    pub status: Option<u16>,
    pub headers: BTreeMap<String, String>,
    pub trailers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VirtualHostContext {
    pub id: VirtualHostId,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PipelineExecutionState {
    pub request_stage_forwarding_ready: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestContext {
    pub id: RequestId,
    pub connection: ConnectionContext,
    pub stage: ProcessingStage,
    fingerprinting_result: Option<FingerprintComputationResult>,
    pub client_network_rules: Vec<ClientNetworkClassificationRule>,
    pub enrichment: RequestEnrichment,
    pub request: HttpRequest,
    pub response: HttpResponse,
    pub virtual_host: Option<VirtualHostContext>,
    pub module_config: BTreeMap<String, BTreeMap<String, String>>,
    pub pipeline_state: PipelineExecutionState,
}

impl RequestContext {
    pub fn new(id: RequestId, connection: ConnectionContext, request: HttpRequest) -> Self {
        Self {
            id,
            connection,
            stage: ProcessingStage::Request,
            fingerprinting_result: None,
            client_network_rules: Vec::new(),
            enrichment: RequestEnrichment::default(),
            request,
            response: HttpResponse::default(),
            virtual_host: None,
            module_config: BTreeMap::new(),
            pipeline_state: PipelineExecutionState::default(),
        }
    }

    pub fn with_fingerprinting_result(mut self, result: FingerprintComputationResult) -> Self {
        self.fingerprinting_result = Some(result);
        self
    }

    pub fn fingerprinting_result(&self) -> Option<&FingerprintComputationResult> {
        self.fingerprinting_result.as_ref()
    }
}

pub struct PipelineModuleContext<'a> {
    pub id: RequestId,
    pub connection: &'a ConnectionContext,
    pub stage: ProcessingStage,
    pub client_network_rules: &'a mut Vec<ClientNetworkClassificationRule>,
    pub enrichment: &'a mut RequestEnrichment,
    pub request: &'a mut HttpRequest,
    pub response: &'a mut HttpResponse,
    pub virtual_host: &'a mut Option<VirtualHostContext>,
    pub module_config: &'a mut BTreeMap<String, BTreeMap<String, String>>,
    pub pipeline_state: &'a mut PipelineExecutionState,
    fingerprinting_result: Option<&'a FingerprintComputationResult>,
}

impl<'a> PipelineModuleContext<'a> {
    pub fn new(ctx: &'a mut RequestContext) -> Self {
        Self {
            id: ctx.id,
            connection: &ctx.connection,
            stage: ctx.stage,
            client_network_rules: &mut ctx.client_network_rules,
            enrichment: &mut ctx.enrichment,
            request: &mut ctx.request,
            response: &mut ctx.response,
            virtual_host: &mut ctx.virtual_host,
            module_config: &mut ctx.module_config,
            pipeline_state: &mut ctx.pipeline_state,
            fingerprinting_result: ctx.fingerprinting_result.as_ref(),
        }
    }

    pub fn fingerprinting_result(&self) -> Option<&FingerprintComputationResult> {
        self.fingerprinting_result
    }

    pub fn replace_request(&mut self, request: HttpRequest) {
        *self.request = request;
    }
}
