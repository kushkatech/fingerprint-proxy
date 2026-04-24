use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub fn extract_ipv6_mapped_ipv4(addr: Ipv6Addr) -> Option<Ipv4Addr> {
    addr.to_ipv4_mapped()
}

pub fn normalize_ipv6_mapped_ip(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V6(ipv6) => extract_ipv6_mapped_ipv4(ipv6)
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ipv6)),
        IpAddr::V4(ipv4) => IpAddr::V4(ipv4),
    }
}

pub fn normalize_ipv6_mapped_socket_addr(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(normalize_ipv6_mapped_ip(addr.ip()), addr.port())
}
