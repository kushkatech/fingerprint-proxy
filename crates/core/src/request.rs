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
    pub fingerprinting_result: Option<FingerprintComputationResult>,
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
}
