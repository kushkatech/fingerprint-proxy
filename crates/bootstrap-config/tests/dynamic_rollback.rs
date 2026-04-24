use fingerprint_proxy_bootstrap_config::config::{DomainConfig, FingerprintHeaderConfig};
use fingerprint_proxy_bootstrap_config::dynamic::atomic_update::DynamicConfigSnapshot;
use fingerprint_proxy_bootstrap_config::dynamic::rollback::{
    select_rollback_candidate, RollbackTarget, SnapshotActivationHistory,
};
use fingerprint_proxy_bootstrap_config::versioning::ConfigRevisionId;
use fingerprint_proxy_core::error::ErrorKind;
use fingerprint_proxy_core::identifiers::ConfigVersion;
use std::sync::Arc;

fn revision_id(value: &str) -> ConfigRevisionId {
    ConfigRevisionId::new(value).expect("valid revision id")
}

fn snapshot(version: &str, ja4_header: &str) -> Arc<DynamicConfigSnapshot> {
    Arc::new(DynamicConfigSnapshot::from_domain_config(DomainConfig {
        version: ConfigVersion::new(version).expect("version"),
        virtual_hosts: Vec::new(),
        fingerprint_headers: FingerprintHeaderConfig {
            ja4t_header: "X-JA4T".to_string(),
            ja4_header: ja4_header.to_string(),
            ja4one_header: "X-JA4One".to_string(),
        },
        client_classification_rules: Vec::new(),
    }))
}

#[test]
fn rollback_previous_selects_latest_non_active_snapshot_deterministically() {
    let active = snapshot("dyn-roll-4", "X-JA4-ACTIVE");
    let history = vec![
        snapshot("dyn-roll-1", "X-JA4-OLD-1"),
        snapshot("dyn-roll-2", "X-JA4-OLD-2A"),
        snapshot("dyn-roll-3", "X-JA4-OLD-3"),
        snapshot("dyn-roll-2", "X-JA4-OLD-2B"),
    ];

    let candidate = select_rollback_candidate(&active, &history, RollbackTarget::Previous)
        .expect("previous rollback candidate");
    let selected = candidate.snapshot();

    assert_eq!(selected.revision_id().as_str(), "dyn-roll-2");
    assert_eq!(
        selected.config().fingerprint_headers.ja4_header,
        "X-JA4-OLD-2B"
    );
}

#[test]
fn rollback_specific_revision_selects_latest_matching_snapshot_deterministically() {
    let active = snapshot("dyn-roll-4", "X-JA4-ACTIVE");
    let history = SnapshotActivationHistory::from_snapshots(vec![
        snapshot("dyn-roll-1", "X-JA4-OLD-1"),
        snapshot("dyn-roll-2", "X-JA4-OLD-2A"),
        snapshot("dyn-roll-3", "X-JA4-OLD-3"),
        snapshot("dyn-roll-2", "X-JA4-OLD-2B"),
    ]);

    let candidate = history
        .select_rollback_candidate(&active, RollbackTarget::Revision(revision_id("dyn-roll-2")))
        .expect("specific revision rollback candidate");
    let selected = candidate.snapshot();

    assert_eq!(selected.revision_id().as_str(), "dyn-roll-2");
    assert_eq!(
        selected.config().fingerprint_headers.ja4_header,
        "X-JA4-OLD-2B"
    );
}

#[test]
fn rollback_to_active_revision_is_rejected() {
    let active = snapshot("dyn-roll-2", "X-JA4-ACTIVE");
    let history = vec![snapshot("dyn-roll-1", "X-JA4-OLD-1")];

    let err = select_rollback_candidate(
        &active,
        &history,
        RollbackTarget::Revision(revision_id("dyn-roll-2")),
    )
    .expect_err("active revision rollback must fail");

    assert_eq!(err.kind, ErrorKind::InvalidConfiguration);
    assert!(err.message.contains("already active"));
}
