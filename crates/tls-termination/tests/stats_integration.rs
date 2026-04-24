use fingerprint_proxy_tls_termination::ConnectionStatsIntegration;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

#[test]
fn connection_stats_integration_invokes_connection_and_error_callbacks() {
    let opened = Arc::new(AtomicU64::new(0));
    let closed = Arc::new(AtomicU64::new(0));
    let upstream_errors = Arc::new(AtomicU64::new(0));

    let integration = ConnectionStatsIntegration::new(
        {
            let opened = Arc::clone(&opened);
            move |_at_unix| {
                opened.fetch_add(1, Ordering::Relaxed);
            }
        },
        {
            let closed = Arc::clone(&closed);
            move || {
                closed.fetch_add(1, Ordering::Relaxed);
            }
        },
        {
            let upstream_errors = Arc::clone(&upstream_errors);
            move |_at_unix| {
                upstream_errors.fetch_add(1, Ordering::Relaxed);
            }
        },
    );

    {
        let _guard = integration.open_connection(120);
        integration.record_upstream_error(125);
        assert_eq!(opened.load(Ordering::Relaxed), 1);
        assert_eq!(closed.load(Ordering::Relaxed), 0);
        assert_eq!(upstream_errors.load(Ordering::Relaxed), 1);
    }

    assert_eq!(opened.load(Ordering::Relaxed), 1);
    assert_eq!(closed.load(Ordering::Relaxed), 1);
    assert_eq!(upstream_errors.load(Ordering::Relaxed), 1);
}
