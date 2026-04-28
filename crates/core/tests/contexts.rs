mod common;

use fingerprint_proxy_core::connection::TransportProtocol;
use fingerprint_proxy_core::identifiers::{ConfigVersion, ConnectionId, RequestId};
use fingerprint_proxy_core::request::HttpRequest;
use fingerprint_proxy_core::{ConnectionContext, RequestContext};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::SystemTime;

#[test]
fn request_context_starts_without_fingerprinting_result() {
    common::init();
    let client = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 12345);
    let dest = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)), 443);

    let connection = ConnectionContext::new(
        ConnectionId(1),
        client,
        dest,
        TransportProtocol::Tcp,
        SystemTime::UNIX_EPOCH,
        ConfigVersion::new("cfg-1").unwrap(),
    );

    let request = HttpRequest::new("GET", "/", "HTTP/1.1");
    let ctx = RequestContext::new(RequestId(2), connection, request);

    assert_eq!(ctx.connection.id.0, 1);
    assert_eq!(ctx.id.0, 2);
    assert_eq!(
        ctx.stage,
        fingerprint_proxy_core::enrichment::ProcessingStage::Request
    );
    assert!(ctx.fingerprinting_result().is_none());
}
