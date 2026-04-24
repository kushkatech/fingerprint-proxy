use std::collections::BTreeMap;
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessingStage {
    Request,
    Response,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleDecision {
    Continue,
    Terminate,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EnrichmentAttributes(pub BTreeMap<String, String>);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientNetworkCidr {
    pub addr: IpAddr,
    pub prefix_len: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientNetworkClassificationRule {
    pub name: String,
    pub cidrs: Vec<ClientNetworkCidr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientNetworkClassification {
    Match(ClientNetworkClassificationMatch),
    NoMatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientNetworkClassificationMatch {
    pub rule_name: String,
    pub rule_index: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RequestEnrichment {
    pub client_network_classification: Option<ClientNetworkClassification>,
}

impl RequestEnrichment {
    pub fn set_client_network_classification(
        &mut self,
        classification: ClientNetworkClassification,
    ) {
        self.client_network_classification = Some(classification);
    }
}
