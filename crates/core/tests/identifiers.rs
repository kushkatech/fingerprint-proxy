mod common;

use fingerprint_proxy_core::identifiers::{ConfigVersion, ConnectionId, RequestId, VirtualHostId};

#[test]
fn config_version_rejects_empty() {
    common::init();
    assert!(ConfigVersion::new("").is_err());
    assert!(ConfigVersion::new("   ").is_err());
    assert_eq!(ConfigVersion::new("v1").unwrap().as_str(), "v1");
}

#[test]
fn identifier_display_formats() {
    common::init();
    assert_eq!(ConnectionId(7).to_string(), "conn:7");
    assert_eq!(RequestId(8).to_string(), "req:8");
    assert_eq!(VirtualHostId(9).to_string(), "vhost:9");
}
