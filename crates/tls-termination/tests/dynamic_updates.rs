use fingerprint_proxy_core::error::ErrorKind;
use fingerprint_proxy_tls_termination::cert_store_update::{
    prepare_certificate_store_update, ActiveCertificateStore, CertificateStoreSnapshot,
};
use fingerprint_proxy_tls_termination::config::{
    CertificateId, CertificateRef, DefaultCertificatePolicy, ServerNamePattern,
    TlsCertificateEntry, TlsSelectionConfig,
};
use fingerprint_proxy_tls_termination::dynamic_update::{
    prepare_routing_table_update, ActiveRoutingTable, RoutingTableSnapshot, VirtualHostRouteEntry,
};
use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::Arc;

fn cert(id: &str) -> CertificateId {
    CertificateId::new(id).expect("valid cert id")
}

fn cert_selection(default_id: &str, sni_id: &str) -> TlsSelectionConfig {
    TlsSelectionConfig {
        default_policy: DefaultCertificatePolicy::UseDefault(CertificateRef {
            id: cert(default_id),
        }),
        certificates: vec![TlsCertificateEntry {
            certificate: CertificateRef { id: cert(sni_id) },
            server_names: vec![ServerNamePattern::Exact("vhost.example.com".to_string())],
        }],
    }
}

fn available_ids(ids: &[&str]) -> BTreeSet<CertificateId> {
    ids.iter().map(|id| cert(id)).collect()
}

fn route_entry(virtual_host_id: u64, sni: &str, destination: SocketAddr) -> VirtualHostRouteEntry {
    VirtualHostRouteEntry {
        virtual_host_id,
        sni_patterns: vec![ServerNamePattern::Exact(sni.to_string())],
        destinations: vec![destination],
    }
}

fn default_cert_id(snapshot: &CertificateStoreSnapshot) -> &str {
    match &snapshot.selection().default_policy {
        DefaultCertificatePolicy::UseDefault(default_cert) => default_cert.id.as_str(),
        DefaultCertificatePolicy::Reject => "reject",
    }
}

#[test]
fn routing_table_updates_swap_prepared_snapshot_atomically() {
    let initial = RoutingTableSnapshot::new(
        "dyn-route-1",
        vec![route_entry(
            11,
            "old.example.com",
            "10.0.0.10:443".parse().expect("socket addr"),
        )],
    )
    .expect("initial routing snapshot");
    let store = ActiveRoutingTable::new(initial);
    let bound = store.active_snapshot().expect("bound active snapshot");

    let prepared = prepare_routing_table_update(
        RoutingTableSnapshot::new(
            "dyn-route-2",
            vec![route_entry(
                22,
                "new.example.com",
                "10.0.0.20:443".parse().expect("socket addr"),
            )],
        )
        .expect("prepared routing snapshot"),
    );
    let activation = store.apply(prepared).expect("apply routing update");

    assert!(Arc::ptr_eq(&bound, &activation.previous_active));
    assert_eq!(bound.revision_id(), "dyn-route-1");
    assert_eq!(bound.routes()[0].virtual_host_id, 11);
    assert_eq!(activation.active.revision_id(), "dyn-route-2");
    assert_eq!(activation.active.routes()[0].virtual_host_id, 22);

    let current = store
        .active_snapshot()
        .expect("current active routing snapshot");
    assert_eq!(current.revision_id(), "dyn-route-2");
}

#[test]
fn certificate_store_updates_swap_prepared_snapshot_atomically() {
    let initial = CertificateStoreSnapshot::new(
        "dyn-cert-store-1",
        cert_selection("cert-a", "cert-a"),
        available_ids(&["cert-a"]),
    )
    .expect("initial cert-store snapshot");
    let store = ActiveCertificateStore::new(initial);
    let bound = store.active_snapshot().expect("bound active cert-store");

    let prepared = prepare_certificate_store_update(
        CertificateStoreSnapshot::new(
            "dyn-cert-store-2",
            cert_selection("cert-b", "cert-b"),
            available_ids(&["cert-b"]),
        )
        .expect("prepared cert-store snapshot"),
    );
    let activation = store
        .apply(prepared)
        .expect("apply cert-store prepared update");

    assert!(Arc::ptr_eq(&bound, &activation.previous_active));
    assert_eq!(bound.revision_id(), "dyn-cert-store-1");
    assert_eq!(default_cert_id(&bound), "cert-a");
    assert_eq!(activation.active.revision_id(), "dyn-cert-store-2");
    assert_eq!(default_cert_id(&activation.active), "cert-b");

    let current = store.active_snapshot().expect("current active cert-store");
    assert_eq!(current.revision_id(), "dyn-cert-store-2");
}

#[test]
fn certificate_store_snapshot_rejects_missing_referenced_material() {
    let err = CertificateStoreSnapshot::new(
        "dyn-cert-store-3",
        cert_selection("cert-a", "cert-a"),
        available_ids(&["cert-b"]),
    )
    .expect_err("missing referenced cert material must fail");

    assert_eq!(err.kind, ErrorKind::InvalidConfiguration);
    assert!(err
        .message
        .contains("missing from prepared certificate store"));
}
