mod common;

use fingerprint_proxy_core::error::ErrorKind;
use fingerprint_proxy_core::{
    extract_ipv6_mapped_ipv4, normalize_ipv6_mapped_ip, normalize_ipv6_mapped_socket_addr,
    parse_ip_address_literal, parse_ipv6_address_literal, strip_ipv6_brackets,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

#[test]
fn ipv6_literal_parsing_accepts_bracketed_and_unbracketed_inputs() {
    common::init();
    let unbracketed = parse_ipv6_address_literal("2001:db8::1").expect("ipv6");
    let bracketed = parse_ipv6_address_literal("[2001:db8::1]").expect("ipv6");
    assert_eq!(unbracketed, bracketed);
}

#[test]
fn ip_literal_parsing_rejects_unbalanced_brackets() {
    common::init();
    let err = parse_ip_address_literal("[2001:db8::1").expect_err("must fail");
    assert_eq!(err.kind, ErrorKind::InvalidConfiguration);
    assert!(err.message.contains("brackets"));
}

#[test]
fn strip_ipv6_brackets_preserves_plain_hosts() {
    common::init();
    assert_eq!(
        strip_ipv6_brackets("example.com").expect("plain host"),
        "example.com"
    );
    assert_eq!(strip_ipv6_brackets("[::1]").expect("ipv6"), "::1");
}

#[test]
fn ipv6_mapped_ipv4_is_extracted_and_normalized() {
    common::init();
    let mapped = Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc000, 0x0201);
    assert_eq!(
        extract_ipv6_mapped_ipv4(mapped),
        Some(Ipv4Addr::new(192, 0, 2, 1))
    );

    let normalized = normalize_ipv6_mapped_ip(IpAddr::V6(mapped));
    assert_eq!(normalized, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
}

#[test]
fn socket_addr_normalization_rewrites_only_mapped_addresses() {
    common::init();
    let mapped = SocketAddr::new(
        IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc000, 0x0201)),
        443,
    );
    let native = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 443);

    assert_eq!(
        normalize_ipv6_mapped_socket_addr(mapped),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 443)
    );
    assert_eq!(normalize_ipv6_mapped_socket_addr(native), native);
}
