use fingerprint_proxy_core::ipv6_mapped::{
    normalize_ipv6_mapped_ip, normalize_ipv6_mapped_socket_addr,
};
use std::net::{IpAddr, SocketAddr};

pub fn normalize_client_connection_addr(client_addr: SocketAddr) -> SocketAddr {
    normalize_ipv6_mapped_socket_addr(client_addr)
}

pub fn normalized_client_ip(client_addr: SocketAddr) -> IpAddr {
    normalize_ipv6_mapped_ip(client_addr.ip())
}

pub fn client_connection_uses_ipv6(client_addr: SocketAddr) -> bool {
    matches!(normalized_client_ip(client_addr), IpAddr::V6(_))
}
