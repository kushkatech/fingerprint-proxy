use fingerprint_proxy_tls_termination::{
    dual_stack_coverage, is_dual_stack_operation_enabled, listener_accepts_peer,
    listener_address_family, ListenerAddressFamily,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

#[test]
fn dual_stack_coverage_reflects_listener_set() {
    let listeners = [
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443),
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 443),
    ];

    let coverage = dual_stack_coverage(&listeners);
    assert!(coverage.has_ipv4);
    assert!(coverage.has_ipv6);
    assert!(is_dual_stack_operation_enabled(&listeners));
}

#[test]
fn ipv6_unspecified_listener_is_treated_as_dual_stack() {
    let listener = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 443);
    assert_eq!(
        listener_address_family(listener),
        ListenerAddressFamily::DualStack
    );

    let mapped_peer = SocketAddr::new(
        IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x7f00, 0x0001)),
        12345,
    );
    assert!(listener_accepts_peer(listener, mapped_peer));
}
