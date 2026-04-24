use fingerprint_proxy_core::error::ErrorKind;
use fingerprint_proxy_upstream::ipv6_routing::{
    connect_tcp_with_routing, ordered_candidate_routes, AddressFamilyPreference,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::net::TcpListener;

#[test]
fn ordered_routes_apply_family_preference_deterministically() {
    let candidates = vec![
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 443),
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 443),
    ];

    let v6_first =
        ordered_candidate_routes(candidates.clone(), AddressFamilyPreference::PreferIpv6);
    assert_eq!(
        v6_first,
        vec![
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 443),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 443),
        ]
    );

    let v4_first = ordered_candidate_routes(candidates, AddressFamilyPreference::PreferIpv4);
    assert_eq!(
        v4_first,
        vec![
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 443),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 443),
        ]
    );
}

#[tokio::test]
async fn connect_with_routing_supports_ipv4_mapped_literals() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let handle = tokio::spawn(async move {
        let _ = listener.accept().await.expect("accept");
    });

    let _stream = connect_tcp_with_routing(
        "::ffff:127.0.0.1",
        port,
        AddressFamilyPreference::PreferIpv6,
    )
    .await
    .expect("connect");

    handle.await.expect("server task");
}

#[tokio::test]
async fn connect_with_routing_rejects_invalid_host_shape() {
    let err = connect_tcp_with_routing("[example.com]", 443, AddressFamilyPreference::PreferIpv6)
        .await
        .expect_err("must fail");
    assert_eq!(err.kind, ErrorKind::InvalidConfiguration);
    assert!(err.message.contains("IPv6 literal"));
}
