use fingerprint_proxy_tls_termination::{
    client_connection_uses_ipv6, normalize_client_connection_addr, normalized_client_ip,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

#[test]
fn mapped_ipv6_client_addr_is_normalized_to_ipv4() {
    let mapped = SocketAddr::new(
        IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc000, 0x0201)),
        44321,
    );

    assert_eq!(
        normalize_client_connection_addr(mapped),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 44321)
    );
    assert_eq!(
        normalized_client_ip(mapped),
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))
    );
    assert!(!client_connection_uses_ipv6(mapped));
}

#[test]
fn native_ipv6_client_addr_is_preserved() {
    let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 44321);
    assert_eq!(normalize_client_connection_addr(addr), addr);
    assert_eq!(normalized_client_ip(addr), IpAddr::V6(Ipv6Addr::LOCALHOST));
    assert!(client_connection_uses_ipv6(addr));
}
