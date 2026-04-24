use crate::ipv6::normalize_upstream_host;
use crate::{FpError, FpResult};
use fingerprint_proxy_core::ipv6_mapped::normalize_ipv6_mapped_socket_addr;
use std::net::{IpAddr, SocketAddr};
use tokio::net::TcpStream;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFamilyPreference {
    PreferIpv6,
    PreferIpv4,
}

pub fn ordered_candidate_routes(
    candidates: Vec<SocketAddr>,
    preference: AddressFamilyPreference,
) -> Vec<SocketAddr> {
    let mut ipv4 = Vec::new();
    let mut ipv6 = Vec::new();

    for candidate in candidates {
        let normalized = normalize_ipv6_mapped_socket_addr(candidate);
        let target = match normalized.ip() {
            IpAddr::V4(_) => &mut ipv4,
            IpAddr::V6(_) => &mut ipv6,
        };
        if !target.contains(&normalized) {
            target.push(normalized);
        }
    }

    match preference {
        AddressFamilyPreference::PreferIpv6 => {
            ipv6.extend(ipv4);
            ipv6
        }
        AddressFamilyPreference::PreferIpv4 => {
            ipv4.extend(ipv6);
            ipv4
        }
    }
}

pub async fn connect_tcp_with_routing(
    upstream_host: &str,
    upstream_port: u16,
    preference: AddressFamilyPreference,
) -> FpResult<TcpStream> {
    let normalized_host = normalize_upstream_host(upstream_host)?;
    let candidates = if let Ok(ip) = normalized_host.parse::<IpAddr>() {
        vec![SocketAddr::new(ip, upstream_port)]
    } else {
        let resolved = tokio::net::lookup_host((normalized_host.as_str(), upstream_port))
            .await
            .map_err(|_| FpError::invalid_protocol_data("upstream connect failed"))?;
        ordered_candidate_routes(resolved.collect(), preference)
    };

    if candidates.is_empty() {
        return Err(FpError::invalid_protocol_data("upstream connect failed"));
    }

    for candidate in candidates {
        if let Ok(stream) = TcpStream::connect(candidate).await {
            return Ok(stream);
        }
    }

    Err(FpError::invalid_protocol_data("upstream connect failed"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn route_ordering_normalizes_mapped_and_prefers_ipv6() {
        let ordered = ordered_candidate_routes(
            vec![
                SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x7f00, 0x0001)),
                    443,
                ),
                SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 443),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443),
            ],
            AddressFamilyPreference::PreferIpv6,
        );

        assert_eq!(
            ordered,
            vec![
                SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 443),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443),
            ]
        );
    }

    #[test]
    fn route_ordering_can_prefer_ipv4() {
        let ordered = ordered_candidate_routes(
            vec![
                SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 443),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443),
            ],
            AddressFamilyPreference::PreferIpv4,
        );

        assert_eq!(
            ordered,
            vec![
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443),
                SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 443),
            ]
        );
    }
}
