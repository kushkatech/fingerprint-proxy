use crate::ipv6::normalize_upstream_host;
use crate::{FpError, FpResult, UPSTREAM_CONNECT_FAILED_MESSAGE};
use fingerprint_proxy_core::ipv6_mapped::normalize_ipv6_mapped_socket_addr;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
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
    connect_tcp_with_routing_and_timeout(upstream_host, upstream_port, preference, None).await
}

pub async fn connect_tcp_with_routing_and_timeout(
    upstream_host: &str,
    upstream_port: u16,
    preference: AddressFamilyPreference,
    connect_timeout: Option<Duration>,
) -> FpResult<TcpStream> {
    let normalized_host = normalize_upstream_host(upstream_host)?;
    let connect_deadline = connect_timeout.map(|timeout| tokio::time::Instant::now() + timeout);
    let candidates = if let Ok(ip) = normalized_host.parse::<IpAddr>() {
        vec![SocketAddr::new(ip, upstream_port)]
    } else {
        let lookup = tokio::net::lookup_host((normalized_host.as_str(), upstream_port));
        let resolved = match connect_deadline {
            Some(deadline) => {
                let Some(remaining) =
                    remaining_connect_budget(deadline, tokio::time::Instant::now())
                else {
                    return Err(FpError::invalid_protocol_data(
                        UPSTREAM_CONNECT_FAILED_MESSAGE,
                    ));
                };
                tokio::time::timeout(remaining, lookup)
                    .await
                    .map_err(|_| FpError::invalid_protocol_data(UPSTREAM_CONNECT_FAILED_MESSAGE))?
                    .map_err(|_| FpError::invalid_protocol_data(UPSTREAM_CONNECT_FAILED_MESSAGE))?
            }
            None => lookup
                .await
                .map_err(|_| FpError::invalid_protocol_data(UPSTREAM_CONNECT_FAILED_MESSAGE))?,
        };
        ordered_candidate_routes(resolved.collect(), preference)
    };

    if candidates.is_empty() {
        return Err(FpError::invalid_protocol_data(
            UPSTREAM_CONNECT_FAILED_MESSAGE,
        ));
    }

    for candidate in candidates {
        let connect = TcpStream::connect(candidate);
        let result = match connect_deadline {
            Some(deadline) => {
                let Some(remaining) =
                    remaining_connect_budget(deadline, tokio::time::Instant::now())
                else {
                    break;
                };
                match tokio::time::timeout(remaining, connect).await {
                    Ok(result) => result,
                    Err(_) => break,
                }
            }
            None => connect.await,
        };
        if let Ok(stream) = result {
            return Ok(stream);
        }
    }

    Err(FpError::invalid_protocol_data(
        UPSTREAM_CONNECT_FAILED_MESSAGE,
    ))
}

fn remaining_connect_budget(
    deadline: tokio::time::Instant,
    now: tokio::time::Instant,
) -> Option<Duration> {
    if now >= deadline {
        None
    } else {
        Some(deadline - now)
    }
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

    #[test]
    fn connect_timeout_budget_is_total_deadline_for_dns_and_candidates() {
        let start = tokio::time::Instant::now();
        let deadline = start + Duration::from_millis(100);

        let before_dns = start;
        let after_dns = start + Duration::from_millis(70);
        let after_candidate = start + Duration::from_millis(100);

        assert_eq!(
            remaining_connect_budget(deadline, before_dns),
            Some(Duration::from_millis(100))
        );
        assert_eq!(
            remaining_connect_budget(deadline, after_dns),
            Some(Duration::from_millis(30))
        );
        assert_eq!(remaining_connect_budget(deadline, after_candidate), None);
        assert_eq!(
            remaining_connect_budget(deadline, start + Duration::from_millis(101)),
            None
        );
    }
}
