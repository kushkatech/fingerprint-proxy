use fingerprint_proxy_bootstrap_config::config::{DomainConfig, FingerprintHeaderConfig};
use fingerprint_proxy_bootstrap_config::dynamic::version_check::{
    detect_revision_change, detect_revision_change_from_configs, RevisionChange,
};
use fingerprint_proxy_bootstrap_config::versioning::ConfigRevisionId;
use fingerprint_proxy_core::identifiers::ConfigVersion;

fn domain_config(version: &str) -> DomainConfig {
    DomainConfig {
        version: ConfigVersion::new(version).expect("version"),
        virtual_hosts: Vec::new(),
        fingerprint_headers: FingerprintHeaderConfig::default(),
        client_classification_rules: Vec::new(),
    }
}

fn revision_id(value: &str) -> ConfigRevisionId {
    ConfigRevisionId::new(value).expect("valid revision id")
}

#[test]
fn no_active_revision_is_initial_load() {
    let candidate = domain_config("rev-1");
    let change = detect_revision_change(None, &candidate);

    assert_eq!(
        change,
        RevisionChange::InitialLoad {
            to: revision_id("rev-1"),
        }
    );
}

#[test]
fn matching_revision_is_unchanged() {
    let candidate = domain_config("rev-1");
    let active = revision_id("rev-1");
    let change = detect_revision_change(Some(&active), &candidate);

    assert_eq!(
        change,
        RevisionChange::Unchanged {
            revision: revision_id("rev-1"),
        }
    );
}

#[test]
fn different_revision_is_changed() {
    let active = domain_config("rev-1");
    let candidate = domain_config("rev-2");
    let change = detect_revision_change_from_configs(Some(&active), &candidate);

    assert_eq!(
        change,
        RevisionChange::Changed {
            from: revision_id("rev-1"),
            to: revision_id("rev-2"),
        }
    );
}
