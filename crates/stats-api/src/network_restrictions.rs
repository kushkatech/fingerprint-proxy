use fingerprint_proxy_bootstrap_config::config::{Cidr, StatsApiNetworkPolicy};
use std::net::IpAddr;

pub fn is_peer_ip_allowed(peer_ip: IpAddr, policy: &StatsApiNetworkPolicy) -> bool {
    match policy {
        StatsApiNetworkPolicy::Disabled => true,
        StatsApiNetworkPolicy::RequireAllowlist(cidrs) => {
            cidrs.iter().any(|c| cidr_contains(c, peer_ip))
        }
    }
}

pub fn cidr_contains(cidr: &Cidr, ip: IpAddr) -> bool {
    match (cidr.addr, ip) {
        (IpAddr::V4(net), IpAddr::V4(addr)) => {
            let prefix = cidr.prefix_len.min(32);
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            (u32::from(net) & mask) == (u32::from(addr) & mask)
        }
        (IpAddr::V6(net), IpAddr::V6(addr)) => {
            let prefix = cidr.prefix_len.min(128);
            let net_u128 = u128::from(net);
            let addr_u128 = u128::from(addr);
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            (net_u128 & mask) == (addr_u128 & mask)
        }
        _ => false,
    }
}
