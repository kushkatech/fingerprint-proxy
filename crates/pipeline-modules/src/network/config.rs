use crate::network::ipv4::{Ipv4Cidr, Ipv4CidrParseError};
use crate::network::ipv6::{Ipv6Cidr, Ipv6CidrParseError};
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkCidrInput {
    pub addr: IpAddr,
    pub prefix_len: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkRuleConfig {
    pub name: String,
    pub cidrs: Vec<NetworkCidrInput>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkListConfig {
    rules: Vec<NetworkRule>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkRule {
    name: String,
    cidrs: NetworkRuleCidrs,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum NetworkRuleCidrs {
    Ipv4(Vec<Ipv4Cidr>),
    Ipv6(Vec<Ipv6Cidr>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkListConfigError {
    EmptyRuleName {
        rule_index: usize,
    },
    EmptyRuleCidrs {
        rule_name: String,
    },
    MixedAddressFamilies {
        rule_name: String,
    },
    InvalidCidr {
        rule_name: String,
        addr: IpAddr,
        prefix_len: u8,
    },
}

impl NetworkListConfig {
    pub fn compile(rules: Vec<NetworkRuleConfig>) -> Result<Self, NetworkListConfigError> {
        let mut compiled = Vec::with_capacity(rules.len());

        for (idx, rule) in rules.into_iter().enumerate() {
            let rule_name = rule.name.trim().to_string();
            if rule_name.is_empty() {
                return Err(NetworkListConfigError::EmptyRuleName { rule_index: idx });
            }
            if rule.cidrs.is_empty() {
                return Err(NetworkListConfigError::EmptyRuleCidrs {
                    rule_name: rule_name.clone(),
                });
            }

            compiled.push(NetworkRule::compile(rule_name, rule.cidrs)?);
        }

        Ok(Self { rules: compiled })
    }

    pub fn rules(&self) -> &[NetworkRule] {
        &self.rules
    }
}

impl NetworkRule {
    fn compile(
        rule_name: String,
        cidrs: Vec<NetworkCidrInput>,
    ) -> Result<Self, NetworkListConfigError> {
        let mut ipv4_cidrs = Vec::new();
        let mut ipv6_cidrs = Vec::new();

        for cidr in cidrs {
            match cidr.addr {
                IpAddr::V4(addr) => {
                    let parsed = Ipv4Cidr::new(addr, cidr.prefix_len)
                        .map_err(|err| map_ipv4_error(err, &rule_name, cidr))?;
                    ipv4_cidrs.push(parsed);
                }
                IpAddr::V6(addr) => {
                    let parsed = Ipv6Cidr::new(addr, cidr.prefix_len)
                        .map_err(|err| map_ipv6_error(err, &rule_name, cidr))?;
                    ipv6_cidrs.push(parsed);
                }
            }
        }

        match (ipv4_cidrs.is_empty(), ipv6_cidrs.is_empty()) {
            (false, true) => Ok(Self {
                name: rule_name,
                cidrs: NetworkRuleCidrs::Ipv4(ipv4_cidrs),
            }),
            (true, false) => Ok(Self {
                name: rule_name,
                cidrs: NetworkRuleCidrs::Ipv6(ipv6_cidrs),
            }),
            (false, false) => Err(NetworkListConfigError::MixedAddressFamilies {
                rule_name: rule_name.to_string(),
            }),
            (true, true) => Err(NetworkListConfigError::EmptyRuleCidrs {
                rule_name: rule_name.to_string(),
            }),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub(crate) fn matches(&self, addr: IpAddr) -> bool {
        match (&self.cidrs, addr) {
            (NetworkRuleCidrs::Ipv4(cidrs), IpAddr::V4(ip)) => {
                cidrs.iter().any(|cidr| cidr.contains(ip))
            }
            (NetworkRuleCidrs::Ipv6(cidrs), IpAddr::V6(ip)) => {
                cidrs.iter().any(|cidr| cidr.contains(ip))
            }
            _ => false,
        }
    }
}

fn map_ipv4_error(
    err: Ipv4CidrParseError,
    rule_name: &str,
    cidr: NetworkCidrInput,
) -> NetworkListConfigError {
    match err {
        Ipv4CidrParseError::PrefixLengthOutOfRange(_) => NetworkListConfigError::InvalidCidr {
            rule_name: rule_name.to_string(),
            addr: cidr.addr,
            prefix_len: cidr.prefix_len,
        },
        _ => NetworkListConfigError::InvalidCidr {
            rule_name: rule_name.to_string(),
            addr: cidr.addr,
            prefix_len: cidr.prefix_len,
        },
    }
}

fn map_ipv6_error(
    err: Ipv6CidrParseError,
    rule_name: &str,
    cidr: NetworkCidrInput,
) -> NetworkListConfigError {
    match err {
        Ipv6CidrParseError::PrefixLengthOutOfRange(_) => NetworkListConfigError::InvalidCidr {
            rule_name: rule_name.to_string(),
            addr: cidr.addr,
            prefix_len: cidr.prefix_len,
        },
        _ => NetworkListConfigError::InvalidCidr {
            rule_name: rule_name.to_string(),
            addr: cidr.addr,
            prefix_len: cidr.prefix_len,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn compiles_ordered_ipv4_and_ipv6_rules() {
        let cfg = NetworkListConfig::compile(vec![
            NetworkRuleConfig {
                name: "trusted-v4".to_string(),
                cidrs: vec![NetworkCidrInput {
                    addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
                    prefix_len: 8,
                }],
            },
            NetworkRuleConfig {
                name: "trusted-v6".to_string(),
                cidrs: vec![NetworkCidrInput {
                    addr: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)),
                    prefix_len: 32,
                }],
            },
        ])
        .expect("valid network list config");

        assert_eq!(cfg.rules().len(), 2);
        assert_eq!(cfg.rules()[0].name(), "trusted-v4");
        assert_eq!(cfg.rules()[1].name(), "trusted-v6");
    }

    #[test]
    fn rejects_mixed_address_families_in_single_rule() {
        let err = NetworkListConfig::compile(vec![NetworkRuleConfig {
            name: "mixed".to_string(),
            cidrs: vec![
                NetworkCidrInput {
                    addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
                    prefix_len: 8,
                },
                NetworkCidrInput {
                    addr: IpAddr::V6(Ipv6Addr::LOCALHOST),
                    prefix_len: 128,
                },
            ],
        }])
        .expect_err("mixed family list must fail");

        assert_eq!(
            err,
            NetworkListConfigError::MixedAddressFamilies {
                rule_name: "mixed".to_string()
            }
        );
    }

    #[test]
    fn rejects_out_of_range_prefix_length() {
        let err = NetworkListConfig::compile(vec![NetworkRuleConfig {
            name: "invalid".to_string(),
            cidrs: vec![NetworkCidrInput {
                addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
                prefix_len: 33,
            }],
        }])
        .expect_err("invalid prefix must fail");

        assert_eq!(
            err,
            NetworkListConfigError::InvalidCidr {
                rule_name: "invalid".to_string(),
                addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
                prefix_len: 33
            }
        );
    }
}
