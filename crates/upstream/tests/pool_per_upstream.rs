use fingerprint_proxy_upstream::pool::config::PoolSizeConfig;
use fingerprint_proxy_upstream::pool::http1::{Http1ReleaseOutcome, KeepAliveConnection};
use fingerprint_proxy_upstream::pool::http2::{Http2InsertOutcome, Http2PooledConnection};
use fingerprint_proxy_upstream::pool::manager::{PoolTransport, UpstreamPoolKey};
use fingerprint_proxy_upstream::pool::per_upstream::PerUpstreamPools;
use fingerprint_proxy_upstream::pool::timeouts::PoolTimeoutConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FakeHttp1Connection {
    id: u64,
    reusable: bool,
}

impl KeepAliveConnection for FakeHttp1Connection {
    fn can_reuse(&self) -> bool {
        self.reusable
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FakeHttp2Connection {
    id: u64,
}

fn key(host: &str, port: u16) -> UpstreamPoolKey {
    UpstreamPoolKey::new(host, port, PoolTransport::Https)
}

#[test]
fn per_upstream_http1_is_isolated_by_pool_key() {
    let mut pools = PerUpstreamPools::<FakeHttp1Connection, FakeHttp2Connection>::new(
        PoolSizeConfig::new(2, 2, 2).expect("sizes"),
        PoolTimeoutConfig::new(10, 20).expect("timeouts"),
    )
    .expect("pools");

    let key_a = key("a.example.test", 443);
    let key_b = key("b.example.test", 443);

    assert_eq!(
        pools.release_http1(
            key_a.clone(),
            FakeHttp1Connection {
                id: 11,
                reusable: true
            },
            100
        ),
        Http1ReleaseOutcome::Pooled
    );
    assert!(pools.try_acquire_http1(&key_b, 101).is_none());

    let reused = pools
        .try_acquire_http1(&key_a, 101)
        .expect("key a has pooled connection");
    assert_eq!(reused.id, 11);
}

#[test]
fn per_upstream_http1_evicts_idle_connections_after_timeout() {
    let mut pools = PerUpstreamPools::<FakeHttp1Connection, FakeHttp2Connection>::new(
        PoolSizeConfig::new(2, 2, 2).expect("sizes"),
        PoolTimeoutConfig::new(5, 20).expect("timeouts"),
    )
    .expect("pools");

    let key_a = key("a.example.test", 443);
    assert_eq!(
        pools.release_http1(
            key_a.clone(),
            FakeHttp1Connection {
                id: 31,
                reusable: true
            },
            10
        ),
        Http1ReleaseOutcome::Pooled
    );
    assert_eq!(pools.http1_idle_count(&key_a), 1);

    assert!(pools.try_acquire_http1(&key_a, 16).is_none());
    assert_eq!(pools.http1_idle_count(&key_a), 0);
}

#[test]
fn per_upstream_http2_timeout_evicts_stale_key_only() {
    let mut pools = PerUpstreamPools::<FakeHttp1Connection, FakeHttp2Connection>::new(
        PoolSizeConfig::new(2, 2, 4).expect("sizes"),
        PoolTimeoutConfig::new(30, 5).expect("timeouts"),
    )
    .expect("pools");

    let key_stale = key("stale.example.test", 443);
    let key_fresh = key("fresh.example.test", 443);

    assert_eq!(
        pools.insert_http2_connection(
            key_stale.clone(),
            Http2PooledConnection::new(FakeHttp2Connection { id: 1 }, 2),
            1
        ),
        Http2InsertOutcome::Inserted
    );
    assert_eq!(
        pools.insert_http2_connection(
            key_fresh.clone(),
            Http2PooledConnection::new(FakeHttp2Connection { id: 2 }, 2),
            1
        ),
        Http2InsertOutcome::Inserted
    );

    let fresh_handle = pools
        .try_acquire_http2_stream(&key_fresh, 4)
        .expect("fresh key stream lease");
    assert!(pools.release_http2_stream(fresh_handle, 4));

    let evicted = pools.evict_expired(8);
    assert_eq!(evicted.http2_connections, 1);
    assert_eq!(pools.http2_connection_count(&key_stale), 0);
    assert_eq!(pools.http2_connection_count(&key_fresh), 1);
}
