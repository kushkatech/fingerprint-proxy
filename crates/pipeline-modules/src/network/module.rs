use crate::network::{
    NetworkCidrInput, NetworkClassification, NetworkClassificationMatch, NetworkClassifier,
    NetworkListConfig, NetworkRuleConfig,
};
use fingerprint_proxy_core::enrichment::{
    ClientNetworkClassification, ClientNetworkClassificationMatch, ClientNetworkClassificationRule,
    ModuleDecision,
};
use fingerprint_proxy_core::error::{FpError, FpResult};
use fingerprint_proxy_core::request::RequestContext;
use fingerprint_proxy_pipeline::module::{PipelineModule, PipelineModuleResult};

pub const MODULE_NAME: &str = "network";

#[derive(Debug, Default)]
pub struct NetworkClassificationModule;

impl NetworkClassificationModule {
    pub fn new() -> Self {
        Self
    }
}

impl PipelineModule for NetworkClassificationModule {
    fn name(&self) -> &'static str {
        MODULE_NAME
    }

    fn handle(&self, ctx: &mut RequestContext) -> PipelineModuleResult {
        let classifier = build_classifier(&ctx.client_network_rules)?;
        let classification = classifier.classify(ctx.connection.client_addr.ip());
        ctx.enrichment
            .set_client_network_classification(map_classification(classification));
        Ok(ModuleDecision::Continue)
    }
}

fn build_classifier(rules: &[ClientNetworkClassificationRule]) -> FpResult<NetworkClassifier> {
    let config_rules = rules
        .iter()
        .map(|rule| NetworkRuleConfig {
            name: rule.name.clone(),
            cidrs: rule
                .cidrs
                .iter()
                .map(|cidr| NetworkCidrInput {
                    addr: cidr.addr,
                    prefix_len: cidr.prefix_len,
                })
                .collect(),
        })
        .collect();

    let config = NetworkListConfig::compile(config_rules).map_err(|err| {
        FpError::invalid_configuration(format!(
            "network module received invalid client classification rules: {err:?}"
        ))
    })?;
    Ok(NetworkClassifier::new(config))
}

fn map_classification(classification: NetworkClassification) -> ClientNetworkClassification {
    match classification {
        NetworkClassification::Match(NetworkClassificationMatch {
            rule_name,
            rule_index,
        }) => ClientNetworkClassification::Match(ClientNetworkClassificationMatch {
            rule_name,
            rule_index,
        }),
        NetworkClassification::NoMatch => ClientNetworkClassification::NoMatch,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fingerprint_proxy_core::connection::{ConnectionContext, TransportProtocol};
    use fingerprint_proxy_core::enrichment::ClientNetworkCidr;
    use fingerprint_proxy_core::identifiers::{ConfigVersion, ConnectionId, RequestId};
    use fingerprint_proxy_core::request::HttpRequest;
    use std::collections::BTreeMap;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::SystemTime;

    fn make_ctx(
        peer: SocketAddr,
        local: SocketAddr,
        rules: Vec<ClientNetworkClassificationRule>,
    ) -> RequestContext {
        let connection = ConnectionContext::new(
            ConnectionId(1),
            peer,
            local,
            TransportProtocol::Tcp,
            SystemTime::UNIX_EPOCH,
            ConfigVersion::new("cfg-1").expect("valid version"),
        );
        let mut ctx = RequestContext::new(
            RequestId(1),
            connection,
            HttpRequest::new("GET", "/", "HTTP/1.1"),
        );
        ctx.client_network_rules = rules;
        ctx
    }

    fn rule(name: &str, cidrs: Vec<(IpAddr, u8)>) -> ClientNetworkClassificationRule {
        ClientNetworkClassificationRule {
            name: name.to_string(),
            cidrs: cidrs
                .into_iter()
                .map(|(addr, prefix_len)| ClientNetworkCidr { addr, prefix_len })
                .collect(),
        }
    }

    #[test]
    fn classifies_using_client_peer_address() {
        let mut ctx = make_ctx(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)), 12345),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)), 443),
            vec![rule(
                "local-only",
                vec![(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 0)), 24)],
            )],
        );

        NetworkClassificationModule::new()
            .handle(&mut ctx)
            .expect("classification");

        assert_eq!(
            ctx.enrichment.client_network_classification,
            Some(ClientNetworkClassification::NoMatch)
        );
    }

    #[test]
    fn writes_match_result_to_request_enrichment() {
        let mut ctx = make_ctx(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 11, 12, 13)), 12345),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), 443),
            vec![rule(
                "corp",
                vec![(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8)],
            )],
        );

        let decision = NetworkClassificationModule::new()
            .handle(&mut ctx)
            .expect("classification");

        assert_eq!(decision, ModuleDecision::Continue);
        assert_eq!(
            ctx.enrichment.client_network_classification,
            Some(ClientNetworkClassification::Match(
                ClientNetworkClassificationMatch {
                    rule_name: "corp".to_string(),
                    rule_index: 0,
                }
            ))
        );
    }

    #[test]
    fn preserves_explicit_no_match_result() {
        let mut ctx = make_ctx(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), 12345),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)), 443),
            vec![rule(
                "corp",
                vec![(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8)],
            )],
        );

        NetworkClassificationModule::new()
            .handle(&mut ctx)
            .expect("classification");

        assert_eq!(
            ctx.enrichment.client_network_classification,
            Some(ClientNetworkClassification::NoMatch)
        );
    }

    #[test]
    fn module_config_does_not_introduce_runtime_bypass_behavior() {
        let mut ctx = make_ctx(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 10, 10, 10)), 12345),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)), 443),
            vec![rule(
                "corp",
                vec![(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8)],
            )],
        );
        let mut cfg = BTreeMap::new();
        cfg.insert("bypass".to_string(), "true".to_string());
        ctx.module_config.insert(MODULE_NAME.to_string(), cfg);

        NetworkClassificationModule::new()
            .handle(&mut ctx)
            .expect("classification");

        assert_eq!(
            ctx.enrichment.client_network_classification,
            Some(ClientNetworkClassification::Match(
                ClientNetworkClassificationMatch {
                    rule_name: "corp".to_string(),
                    rule_index: 0,
                }
            ))
        );
    }
}
