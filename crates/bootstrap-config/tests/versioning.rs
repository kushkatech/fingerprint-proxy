use fingerprint_proxy_bootstrap_config::config::{DomainConfig, FingerprintHeaderConfig};
use fingerprint_proxy_bootstrap_config::versioning::{
    ConfigRevision, ConfigRevisionCatalog, ConfigRevisionId, ConfigVersionSelector,
};
use fingerprint_proxy_core::error::ErrorKind;
use fingerprint_proxy_core::identifiers::ConfigVersion;

fn revision_id(value: &str) -> ConfigRevisionId {
    ConfigRevisionId::new(value).expect("valid revision id")
}

#[test]
fn revision_id_rejects_blank_values() {
    let err = ConfigRevisionId::new("   ").expect_err("blank id should fail");
    assert_eq!(err.kind, ErrorKind::InvalidConfiguration);
    assert_eq!(err.message, "config revision identifier must be non-empty");
}

#[test]
fn catalog_requires_strictly_increasing_order() {
    let revisions = vec![
        ConfigRevision::new(revision_id("v1"), 1),
        ConfigRevision::new(revision_id("v2"), 1),
    ];

    let err = ConfigRevisionCatalog::new(revisions).expect_err("non-increasing order must fail");
    assert_eq!(err.kind, ErrorKind::InvalidConfiguration);
    assert_eq!(
        err.message,
        "config revision ordering must be strictly increasing at index 1"
    );
}

#[test]
fn catalog_requires_unique_revision_identifiers() {
    let revisions = vec![
        ConfigRevision::new(revision_id("v1"), 1),
        ConfigRevision::new(revision_id("v1"), 2),
    ];

    let err =
        ConfigRevisionCatalog::new(revisions).expect_err("duplicate revision identifier fails");
    assert_eq!(err.kind, ErrorKind::InvalidConfiguration);
    assert_eq!(err.message, "duplicate config revision identifier: v1");
}

#[test]
fn catalog_selection_supports_latest_and_specific() {
    let revisions = vec![
        ConfigRevision::new(revision_id("v1"), 10),
        ConfigRevision::new(revision_id("v2"), 20),
        ConfigRevision::new(revision_id("v3"), 30),
    ];

    let catalog = ConfigRevisionCatalog::new(revisions).expect("valid catalog");
    assert_eq!(catalog.len(), 3);
    assert!(!catalog.is_empty());

    let latest = catalog
        .select(&ConfigVersionSelector::Latest)
        .expect("latest exists");
    assert_eq!(latest.id.as_str(), "v3");
    assert_eq!(latest.order.as_u64(), 30);

    let specific = catalog
        .select(&ConfigVersionSelector::Specific(revision_id("v2")))
        .expect("specific revision exists");
    assert_eq!(specific.id.as_str(), "v2");
    assert_eq!(specific.order.as_u64(), 20);
}

#[test]
fn specific_selection_of_unknown_revision_returns_none() {
    let revisions = vec![ConfigRevision::new(revision_id("v1"), 1)];
    let catalog = ConfigRevisionCatalog::new(revisions).expect("valid catalog");

    assert!(catalog
        .select(&ConfigVersionSelector::Specific(revision_id("missing")))
        .is_none());
}

#[test]
fn domain_config_revision_id_maps_existing_config_version() {
    let domain = DomainConfig {
        version: ConfigVersion::new("domain-rev-1").expect("version"),
        virtual_hosts: Vec::new(),
        fingerprint_headers: FingerprintHeaderConfig::default(),
        client_classification_rules: Vec::new(),
    };

    let revision_id = domain.revision_id();
    assert_eq!(revision_id.as_str(), "domain-rev-1");
}
