use fingerprint_proxy_core::error::ErrorKind;
use fingerprint_proxy_upstream::http2::{Http2Connector, UpstreamTransport};
use fingerprint_proxy_upstream::ipv6::{
    normalize_upstream_host, upstream_connect_target, upstream_tls_server_name,
};
use fingerprint_proxy_upstream::manager::UpstreamConnectionManager;
use rustls::pki_types::ServerName;

#[test]
fn normalize_upstream_host_supports_ipv6_and_mapped_literals() {
    assert_eq!(
        normalize_upstream_host("::1").expect("ipv6"),
        "::1".to_string()
    );
    assert_eq!(
        normalize_upstream_host("[::1]").expect("ipv6"),
        "::1".to_string()
    );
    assert_eq!(
        normalize_upstream_host("::ffff:192.0.2.10").expect("mapped"),
        "192.0.2.10".to_string()
    );
}

#[test]
fn upstream_connect_target_formats_ipv6_and_non_ipv6_hosts() {
    assert_eq!(
        upstream_connect_target("::1", 8443).expect("target"),
        "[::1]:8443".to_string()
    );
    assert_eq!(
        upstream_connect_target("::ffff:192.0.2.10", 8443).expect("target"),
        "192.0.2.10:8443".to_string()
    );
    assert_eq!(
        upstream_connect_target("example.com", 8443).expect("target"),
        "example.com:8443".to_string()
    );
}

#[test]
fn upstream_tls_server_name_supports_dns_and_ip_literals() {
    let dns = upstream_tls_server_name("example.com").expect("dns");
    let ip = upstream_tls_server_name("::1").expect("ip");
    assert!(matches!(dns, ServerName::DnsName(_)));
    assert!(matches!(ip, ServerName::IpAddress(_)));
}

#[test]
fn invalid_upstream_host_shapes_are_rejected_deterministically() {
    let err = normalize_upstream_host("[example.com]").expect_err("must fail");
    assert_eq!(err.kind, ErrorKind::InvalidConfiguration);

    let err = normalize_upstream_host("2001:db8::zzzz").expect_err("must fail");
    assert_eq!(err.kind, ErrorKind::InvalidConfiguration);
}

#[tokio::test]
async fn manager_and_http2_connector_use_ipv6_host_validation() {
    let manager = UpstreamConnectionManager::with_system_roots();
    let err = match manager
        .connect_http1("[example.com]", 443, UpstreamTransport::Https)
        .await
    {
        Ok(_) => panic!("must fail"),
        Err(err) => err,
    };
    assert_eq!(err.kind, ErrorKind::InvalidConfiguration);
    assert!(err.message.contains("IPv6 literal"));

    let connector = Http2Connector::with_system_roots();
    let err = match connector
        .connect("[example.com]", 443, UpstreamTransport::Https)
        .await
    {
        Ok(_) => panic!("must fail"),
        Err(err) => err,
    };
    assert_eq!(err.kind, ErrorKind::InvalidConfiguration);
    assert!(err.message.contains("IPv6 literal"));
}
