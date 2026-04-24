use fingerprint_proxy_bootstrap_config::config::{
    CertificateRef, DomainConfig, FingerprintHeaderConfig, ServerNamePattern, UpstreamConfig,
    UpstreamProtocol, VirtualHostConfig, VirtualHostMatch, VirtualHostProtocolConfig,
    VirtualHostTlsConfig,
};
use fingerprint_proxy_bootstrap_config::dynamic::atomic_update::{
    prepare_candidate_snapshot, ActiveSnapshotStore, DynamicConfigSnapshot,
};
use fingerprint_proxy_bootstrap_config::dynamic::validation::validate_candidate_domain_config;
use fingerprint_proxy_core::identifiers::ConfigVersion;
use std::collections::BTreeMap;
use std::sync::Arc;

fn domain_config(version: &str, ja4_header: &str, upstream_host: &str) -> DomainConfig {
    DomainConfig {
        version: ConfigVersion::new(version).expect("version"),
        virtual_hosts: vec![VirtualHostConfig {
            id: 1,
            match_criteria: VirtualHostMatch {
                sni: vec![ServerNamePattern::Exact("atomic.example.com".to_string())],
                destination: Vec::new(),
            },
            tls: VirtualHostTlsConfig {
                certificate: CertificateRef {
                    id: "cert-a".to_string(),
                },
                minimum_tls_version: None,
                cipher_suites: Vec::new(),
            },
            upstream: UpstreamConfig {
                protocol: UpstreamProtocol::Http,
                allowed_upstream_app_protocols: None,
                host: upstream_host.to_string(),
                port: 8080,
            },
            protocol: VirtualHostProtocolConfig {
                allow_http1: true,
                allow_http2: true,
                allow_http3: false,
            },
            module_config: BTreeMap::new(),
        }],
        fingerprint_headers: FingerprintHeaderConfig {
            ja4t_header: "X-JA4T".to_string(),
            ja4_header: ja4_header.to_string(),
            ja4one_header: "X-JA4One".to_string(),
        },
        client_classification_rules: Vec::new(),
    }
}

#[test]
fn atomic_activation_swaps_whole_snapshot_without_mutating_bound_snapshot() {
    let initial_candidate = validate_candidate_domain_config(domain_config(
        "dyn-atomic-1",
        "X-JA4-OLD",
        "old-upstream.internal",
    ))
    .expect("initial candidate");
    let initial_snapshot = DynamicConfigSnapshot::from_validated_candidate(initial_candidate);
    let store = ActiveSnapshotStore::new(initial_snapshot);

    let bound_snapshot = store.active_snapshot().expect("initial active snapshot");

    let next_candidate = validate_candidate_domain_config(domain_config(
        "dyn-atomic-2",
        "X-JA4-NEW",
        "new-upstream.internal",
    ))
    .expect("next candidate");
    let activation = store
        .activate(prepare_candidate_snapshot(next_candidate))
        .expect("activate snapshot");

    assert!(Arc::ptr_eq(&bound_snapshot, &activation.previous_active));
    assert_eq!(
        activation.previous_active.revision_id().as_str(),
        "dyn-atomic-1"
    );
    assert_eq!(activation.active.revision_id().as_str(), "dyn-atomic-2");

    // Existing bound snapshot remains fully old.
    assert_eq!(bound_snapshot.revision_id().as_str(), "dyn-atomic-1");
    assert_eq!(
        bound_snapshot.config().fingerprint_headers.ja4_header,
        "X-JA4-OLD"
    );
    assert_eq!(
        bound_snapshot.config().virtual_hosts[0].upstream.host,
        "old-upstream.internal"
    );

    let current = store.active_snapshot().expect("latest active snapshot");
    assert_eq!(current.revision_id().as_str(), "dyn-atomic-2");
    assert_eq!(current.config().fingerprint_headers.ja4_header, "X-JA4-NEW");
    assert_eq!(
        current.config().virtual_hosts[0].upstream.host,
        "new-upstream.internal"
    );
}
