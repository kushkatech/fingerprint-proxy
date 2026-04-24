use crate::network::config::NetworkListConfig;
use crate::network::ipv6::normalize_client_network_ip;
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkClassifier {
    config: NetworkListConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkClassification {
    Match(NetworkClassificationMatch),
    NoMatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkClassificationMatch {
    pub rule_name: String,
    pub rule_index: usize,
}

impl NetworkClassifier {
    pub fn new(config: NetworkListConfig) -> Self {
        Self { config }
    }

    pub fn classify(&self, addr: IpAddr) -> NetworkClassification {
        let normalized_addr = normalize_client_network_ip(addr);
        for (idx, rule) in self.config.rules().iter().enumerate() {
            if rule.matches(normalized_addr) {
                return NetworkClassification::Match(NetworkClassificationMatch {
                    rule_name: rule.name().to_string(),
                    rule_index: idx,
                });
            }
        }

        NetworkClassification::NoMatch
    }
}

impl NetworkClassification {
    pub fn is_match(&self) -> bool {
        matches!(self, Self::Match(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::config::{NetworkCidrInput, NetworkRuleConfig};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn classifier_from_rules(rules: Vec<NetworkRuleConfig>) -> NetworkClassifier {
        let config = NetworkListConfig::compile(rules).expect("valid config");
        NetworkClassifier::new(config)
    }

    #[test]
    fn classifies_ipv4_addresses() {
        let classifier = classifier_from_rules(vec![NetworkRuleConfig {
            name: "corp-v4".to_string(),
            cidrs: vec![NetworkCidrInput {
                addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
                prefix_len: 8,
            }],
        }]);

        let result = classifier.classify(IpAddr::V4(Ipv4Addr::new(10, 23, 45, 67)));
        assert_eq!(
            result,
            NetworkClassification::Match(NetworkClassificationMatch {
                rule_name: "corp-v4".to_string(),
                rule_index: 0
            })
        );
        assert!(result.is_match());
    }

    #[test]
    fn classifies_ipv6_addresses() {
        let classifier = classifier_from_rules(vec![NetworkRuleConfig {
            name: "corp-v6".to_string(),
            cidrs: vec![NetworkCidrInput {
                addr: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)),
                prefix_len: 32,
            }],
        }]);

        let result = classifier.classify(IpAddr::V6(
            "2001:db8:abcd::1".parse::<Ipv6Addr>().expect("valid"),
        ));
        assert_eq!(
            result,
            NetworkClassification::Match(NetworkClassificationMatch {
                rule_name: "corp-v6".to_string(),
                rule_index: 0
            })
        );
    }

    #[test]
    fn classifies_ipv6_mapped_ipv4_addresses_using_ipv4_rules() {
        let classifier = classifier_from_rules(vec![NetworkRuleConfig {
            name: "corp-v4".to_string(),
            cidrs: vec![NetworkCidrInput {
                addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
                prefix_len: 8,
            }],
        }]);

        let mapped = IpAddr::V6("::ffff:10.23.45.67".parse::<Ipv6Addr>().expect("valid"));
        let result = classifier.classify(mapped);
        assert_eq!(
            result,
            NetworkClassification::Match(NetworkClassificationMatch {
                rule_name: "corp-v4".to_string(),
                rule_index: 0
            })
        );
    }

    #[test]
    fn returns_no_match_for_unclassified_address() {
        let classifier = classifier_from_rules(vec![NetworkRuleConfig {
            name: "corp-v4".to_string(),
            cidrs: vec![NetworkCidrInput {
                addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)),
                prefix_len: 24,
            }],
        }]);

        let result = classifier.classify(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)));
        assert_eq!(result, NetworkClassification::NoMatch);
        assert!(!result.is_match());
    }

    #[test]
    fn applies_first_match_precedence_for_overlapping_rules() {
        let classifier = classifier_from_rules(vec![
            NetworkRuleConfig {
                name: "broad".to_string(),
                cidrs: vec![NetworkCidrInput {
                    addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
                    prefix_len: 8,
                }],
            },
            NetworkRuleConfig {
                name: "narrow".to_string(),
                cidrs: vec![NetworkCidrInput {
                    addr: IpAddr::V4(Ipv4Addr::new(10, 1, 0, 0)),
                    prefix_len: 16,
                }],
            },
        ]);

        let result = classifier.classify(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)));
        assert_eq!(
            result,
            NetworkClassification::Match(NetworkClassificationMatch {
                rule_name: "broad".to_string(),
                rule_index: 0
            })
        );
    }
}
