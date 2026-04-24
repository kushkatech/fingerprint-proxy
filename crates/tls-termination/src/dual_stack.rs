use crate::ipv6::normalize_client_connection_addr;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenerAddressFamily {
    Ipv4Only,
    Ipv6Only,
    DualStack,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DualStackCoverage {
    pub has_ipv4: bool,
    pub has_ipv6: bool,
}

pub fn listener_address_family(bind_addr: SocketAddr) -> ListenerAddressFamily {
    match bind_addr.ip() {
        IpAddr::V4(_) => ListenerAddressFamily::Ipv4Only,
        IpAddr::V6(ipv6) if ipv6 == Ipv6Addr::UNSPECIFIED => ListenerAddressFamily::DualStack,
        IpAddr::V6(_) => ListenerAddressFamily::Ipv6Only,
    }
}

pub fn dual_stack_coverage(bind_addrs: &[SocketAddr]) -> DualStackCoverage {
    let mut coverage = DualStackCoverage::default();

    for addr in bind_addrs {
        match listener_address_family(*addr) {
            ListenerAddressFamily::Ipv4Only => coverage.has_ipv4 = true,
            ListenerAddressFamily::Ipv6Only => coverage.has_ipv6 = true,
            ListenerAddressFamily::DualStack => {
                coverage.has_ipv4 = true;
                coverage.has_ipv6 = true;
            }
        }
    }

    coverage
}

pub fn is_dual_stack_operation_enabled(bind_addrs: &[SocketAddr]) -> bool {
    let coverage = dual_stack_coverage(bind_addrs);
    coverage.has_ipv4 && coverage.has_ipv6
}

pub fn listener_accepts_peer(listener_addr: SocketAddr, peer_addr: SocketAddr) -> bool {
    let normalized_peer = normalize_client_connection_addr(peer_addr);
    match listener_address_family(listener_addr) {
        ListenerAddressFamily::DualStack => true,
        ListenerAddressFamily::Ipv4Only => normalized_peer.is_ipv4(),
        ListenerAddressFamily::Ipv6Only => normalized_peer.is_ipv6(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn detects_listener_address_families_deterministically() {
        assert_eq!(
            listener_address_family(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443)),
            ListenerAddressFamily::Ipv4Only
        );
        assert_eq!(
            listener_address_family(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 443)),
            ListenerAddressFamily::Ipv6Only
        );
        assert_eq!(
            listener_address_family(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 443)),
            ListenerAddressFamily::DualStack
        );
    }

    #[test]
    fn coverage_reports_dual_stack_when_both_families_are_present() {
        let single_v4 = [SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443)];
        let split = [
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 443),
        ];
        let dual = [SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 443)];

        assert!(!is_dual_stack_operation_enabled(&single_v4));
        assert!(is_dual_stack_operation_enabled(&split));
        assert!(is_dual_stack_operation_enabled(&dual));
    }

    #[test]
    fn listener_acceptance_normalizes_mapped_ipv4_peers() {
        let v4_listener = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);
        let v6_listener = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 443);
        let dual_listener = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 443);
        let mapped_peer = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x7f00, 0x0001)),
            12345,
        );

        assert!(listener_accepts_peer(v4_listener, mapped_peer));
        assert!(!listener_accepts_peer(v6_listener, mapped_peer));
        assert!(listener_accepts_peer(dual_listener, mapped_peer));
    }
}
